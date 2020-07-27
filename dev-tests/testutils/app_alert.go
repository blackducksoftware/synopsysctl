package testutils

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/blackducksoftware/synopsysctl/pkg/alert"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// GetLatestAlertVersion ...
func GetLatestAlertVersion() string {
	if TestConfig.Alert.Version != "" {
		return TestConfig.Alert.Version
	}
	return "5.3.2"
}

// NewAlertTester ...
func NewAlertTester() *AlertTester {
	t := AlertTester{
		AppName: util.AlertName,
	}
	// Get default values for an alert test
	t.Name = GenName(t.AppName)
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestAlertVersion()
	t.Labels = ""

	// Config for Alert
	t.FlagTree = alert.FlagTree{}
	t.FlagTree.StandAlone = "TRUE"
	t.FlagTree.PersistentStorage = "TRUE"
	t.FlagTree.ExposeService = "NODEPORT"
	return &t
}

// AlertTester ...
type AlertTester struct {
	AppName   string
	Name      string
	Namespace string
	Version   string
	Labels    string
	FlagTree  alert.FlagTree
}

// WaitUntilReady ...
func (t AlertTester) WaitUntilReady() {
	err := util.WaitForPodsToAppear(KubeClient, t.Namespace, t.Labels)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	util.WaitForPodsToBeRunningOrComplete(KubeClient, t.Namespace, t.Labels)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	util.WaitForPodsToStopTerminating(KubeClient, t.Namespace)
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

// Verify ...
func (t AlertTester) Verify() error {
	checks := []func() error{
		t.checkPersistentStorage,
		t.checkStandalone,
		t.checkExposeService,
		t.checkSecurityContexts,
	}
	var err error
	for _, check := range checks {
		err = check()
		if err != nil {
			return err
		}
	}
	return nil
}

func (t AlertTester) getIDHelper(podName string) string {
	// podName format: <name>-alert-<podname>
	// podID format: alert-<podname>
	rePattern := fmt.Sprintf("%s-([a-z]+[-a-z]*[a-z])(-[0-9]+)*", t.Name)
	r, _ := regexp.Compile(rePattern)
	matches := r.FindStringSubmatch(podName)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func (t AlertTester) deploymentWithNameExists(deploymentName, namespace string) bool {
	targetDeploymentID := deploymentName

	found := false

	deploymentList, err := util.ListDeployments(KubeClient, namespace, "")
	if err != nil {
		return false
	}
	for _, deployment := range deploymentList.Items {
		deploymentID := t.getIDHelper(deployment.Name)
		if deploymentID == targetDeploymentID {
			found = true
			break
		}
	}
	return found
}

func (t AlertTester) serviceWithNameExists(serviceName, namespace string) bool {
	targetServiceID := serviceName

	found := false

	serviceList, err := util.ListServices(KubeClient, namespace, "")
	if err != nil {
		return false
	}
	for _, svc := range serviceList.Items {
		serviceID := t.getIDHelper(svc.Name)
		if serviceID == targetServiceID {
			found = true
			break
		}
	}
	return found
}

func (t AlertTester) configMapWithNameExists(configMapName, namespace string) bool {
	targetConfigMapID := configMapName

	found := false

	configMapList, err := util.ListConfigMaps(KubeClient, namespace, "")
	if err != nil {
		return false
	}
	for _, cm := range configMapList.Items {
		configMapID := t.getIDHelper(cm.Name)
		if configMapID == targetConfigMapID {
			found = true
			break
		}
	}
	return found
}

func (t AlertTester) checkPersistentStorage() error {
	pvcList, err := util.ListPVCs(KubeClient, t.Namespace, "")
	if err != nil {
		return err
	}
	if strings.ToUpper(t.FlagTree.PersistentStorage) == "TRUE" {
		// Verify PVCs exist
		if len(pvcList.Items) == 0 {
			return fmt.Errorf("persistentStorage is enabled but found %+v PVCs", len(pvcList.Items))
		}
	} else {
		// Verify PVCs do not exist
		if len(pvcList.Items) != 0 {
			return fmt.Errorf("persistentStorage is disabled but found %+v PVCs", len(pvcList.Items))
		}
	}
	return nil
}

func (t AlertTester) checkStandalone() error {
	// Verify Deployment <name>-alert-alert
	foundDeployment := t.deploymentWithNameExists("alert-cfssl", t.Namespace)
	if strings.ToUpper(t.FlagTree.StandAlone) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("StandAlone is '%+v' but foundDeployment='%+v'", t.FlagTree.StandAlone, foundDeployment)
	}

	// Verify Service <name>-alert-cfssl
	foundService := t.serviceWithNameExists("alert-cfssl", t.Namespace)
	if strings.ToUpper(t.FlagTree.StandAlone) != strings.ToUpper(strconv.FormatBool(foundService)) {
		return fmt.Errorf("StandAlone is '%+v' but foundService='%+v'", t.FlagTree.StandAlone, foundService)
	}
	return nil
}

func (t AlertTester) checkExposeService() error {
	serviceList, err := util.ListServices(KubeClient, t.Namespace, "")
	if err != nil {
		return err
	}
	if t.FlagTree.ExposeService != util.NONE {
		if t.FlagTree.ExposeService != util.OPENSHIFT {
			// Get Exposed Service
			var exposedService *corev1.Service
			for _, svc := range serviceList.Items {
				if svc.Spec.Type != corev1.ServiceTypeClusterIP {
					exposedService = &svc
					break
				}
			}
			if exposedService == nil {
				return fmt.Errorf("expected LoadBalancer or NodePort but failed to find the exposed service")
			}
			switch t.FlagTree.ExposeService {
			case util.LOADBALANCER:
				if exposedService.Spec.Type != corev1.ServiceTypeLoadBalancer {
					return fmt.Errorf("expected LoadBalancer but got %+v", exposedService.Spec.Type)
				}
			case util.NODEPORT:
				if exposedService.Spec.Type != corev1.ServiceTypeNodePort {
					return fmt.Errorf("expected NodePort but got %+v", exposedService.Spec.Type)
				}
			}
		} else {
			routeClient := util.GetRouteClient(Restconfig, KubeClient, t.Namespace)
			routes, err := util.ListRoutes(routeClient, t.Namespace, t.Labels)
			if err != nil {
				return fmt.Errorf("failed to get routes")
			}
			if len(routes.Items) != 1 {
				return fmt.Errorf("expected 1 route but found %+v routes", len(routes.Items))
			}
		}
	}
	return nil
}

func alertPodIDToPodSecurityContextIDHelper(podID string) string {
	podIDToPodSecurityContextID := map[string]string{
		"alert-postgres": "postgres",
		"alert-cfssl":    "cfssl",
		"alert":          "alert",
	}
	if val, ok := podIDToPodSecurityContextID[podID]; ok {
		return val
	}
	return ""
}

func alertPodIDToSecurityContextIDsHelper(podID string) []string {
	podIDToSecurityContextIDs := map[string][]string{}
	if val, ok := podIDToSecurityContextIDs[podID]; ok {
		return val
	}
	return []string{}
}

func (t AlertTester) checkSecurityContexts() error {
	userSecurityContexts := map[string]corev1.PodSecurityContext{}
	if t.FlagTree.SecurityContextFilePath != "" {
		data, err := util.ReadFileData(t.FlagTree.SecurityContextFilePath)
		if err != nil {
			return fmt.Errorf("failed to read security context file: %+v", err)
		}

		err = json.Unmarshal([]byte(data), &userSecurityContexts)
		if err != nil {
			return fmt.Errorf("failed to unmarshal security contexts: %+v", err)
		}
	}

	podList, err := util.ListPodsWithLabels(KubeClient, t.Namespace, t.Labels)
	if err != nil {
		return fmt.Errorf("failed to list pods: %+v", err)
	}

	// Get Security Contexts of each Pod
	podSecurityContextMap := map[string]*corev1.PodSecurityContext{}
	securityContextMap := map[string][]*corev1.SecurityContext{}
	for _, po := range podList.Items {
		poID := t.getIDHelper(po.Name)
		if poID == "" {
			continue
		}
		defaultPodSecurityContext := &corev1.PodSecurityContext{
			FSGroup: util.IntToInt64(0),
		}
		emptyPodSecurityContext := &corev1.PodSecurityContext{}
		if po.Spec.SecurityContext != nil {
			if po.Spec.SecurityContext != nil && !reflect.DeepEqual(po.Spec.SecurityContext, defaultPodSecurityContext) && !reflect.DeepEqual(po.Spec.SecurityContext, emptyPodSecurityContext) {
				podSecurityContextMap[poID] = po.Spec.SecurityContext
			}
		}
		for _, container := range po.Spec.Containers {
			if container.SecurityContext != nil && container.Name != "synopsys-init" {
				if _, ok := securityContextMap[poID]; ok {
					securityContextMap[poID] = append(securityContextMap[poID], container.SecurityContext)
				} else {
					securityContextMap[poID] = []*corev1.SecurityContext{container.SecurityContext}
				}
			}
		}
	}

	// Check if security contexts were provided then they were found
	if len(userSecurityContexts) == 0 && (len(podSecurityContextMap) > 0 || len(securityContextMap) > 0) {
		return fmt.Errorf("no security contexts were set but found %d PodSecurityContexts and %d SecurityContexts", len(podSecurityContextMap), len(securityContextMap))
	}
	if len(userSecurityContexts) > 0 && (len(podSecurityContextMap) == 0 && len(securityContextMap) == 0) {
		return fmt.Errorf("security contexts were set but found %d PodSecurityContexts and %d SecurityContexts", len(podSecurityContextMap), len(securityContextMap))
	}

	// Check Pod Security Context values that were found
	for poID, podSecurityContext := range podSecurityContextMap {
		pscID := alertPodIDToPodSecurityContextIDHelper(poID)
		if userSecurityContext, ok := userSecurityContexts[pscID]; ok {
			if podSecurityContext.FSGroup != nil && *userSecurityContext.FSGroup != *podSecurityContext.FSGroup {
				return fmt.Errorf("PodSecurityContext FSGroup mismatch for %s: got %+v; expected %+v", pscID, podSecurityContext.FSGroup, userSecurityContext.FSGroup)
			}
			if podSecurityContext.RunAsGroup != nil && *userSecurityContext.RunAsGroup != *podSecurityContext.RunAsGroup {
				return fmt.Errorf("PodSecurityContext RunAsGroup mismatch for %s: got %+v; expected %+v", pscID, podSecurityContext.RunAsGroup, userSecurityContext.RunAsGroup)
			}
			if podSecurityContext.RunAsUser != nil && *userSecurityContext.RunAsUser != *podSecurityContext.RunAsUser {
				return fmt.Errorf("PodSecurityContext RunAsUser mismatch for %s: got %+v; expected %+v", pscID, podSecurityContext.RunAsUser, userSecurityContext.RunAsUser)
			}
		}
	}

	// Check Security Context values that were found
	for poID, foundSecurityContexts := range securityContextMap {
		for _, foundSecurityContext := range foundSecurityContexts { // for each security context that was found
			// Get names of Security Contexts for the Pod
			scIDs := alertPodIDToSecurityContextIDsHelper(poID)

			// Check if the found Security Context matches a Security Context provided by the user
			foundMatch := false
			for _, scID := range scIDs {
				// Check if the user provided the Security Context
				if userSecurityContext, ok := userSecurityContexts[scID]; ok {
					if foundSecurityContext.RunAsGroup != nil && *userSecurityContext.RunAsGroup != *foundSecurityContext.RunAsGroup {
						continue
						// return fmt.Errorf("SecurityContext RunAsGroup mismatch for %s: got %+v; expected %+v", poID, securityContext.RunAsGroup, userSecurityContext.RunAsGroup)
					}
					if foundSecurityContext.RunAsUser != nil && *userSecurityContext.RunAsUser != *foundSecurityContext.RunAsUser {
						continue
						// return fmt.Errorf("SecurityContext RunAsUser mismatch for %s: got %+v; expected %+v", poID, securityContext.RunAsUser, userSecurityContext.RunAsUser)
					}
					foundMatch = true
					break
				}
			}
			if !foundMatch {
				return fmt.Errorf("no Security Contexts in containers %+v matched for Pod %s", scIDs, poID)
			}
		}
	}

	return nil
}
