package testutils

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/blackduck"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

// GetLatestBlackDuckVersion ...
func GetLatestBlackDuckVersion() string {
	if TestConfig.BlackDuck.Version != "" {
		return TestConfig.BlackDuck.Version
	}
	return "2020.4.0"
}

// GetBlackDuckTLSCertPath ...
func GetBlackDuckTLSCertPath() string {
	if TestConfig.BlackDuck.TLSCertPath != "" {
		return TestConfig.BlackDuck.TLSCertPath
	}
	return GetMockTLSCertificate()
}

// GetBlackDuckTLSKeyPath ...
func GetBlackDuckTLSKeyPath() string {
	if TestConfig.BlackDuck.TLSKeyPath != "" {
		return TestConfig.BlackDuck.TLSKeyPath
	}
	return GetMockTLSKey()
}

// NewBlackDuckTester ...
func NewBlackDuckTester() *BlackDuckTester {
	t := BlackDuckTester{
		AppName: util.BlackDuckName,
	}
	// Get default values for an Black Duck test
	t.Name = GenName(t.AppName)
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestBlackDuckVersion()
	t.Labels = ""

	// Config for Black Duck
	t.FlagTree = blackduck.FlagTree{}
	t.FlagTree.PersistentStorage = "TRUE"
	t.FlagTree.ExposeService = "NODEPORT"
	return &t
}

// BlackDuckTester ...
type BlackDuckTester struct {
	AppName   string
	Name      string
	Namespace string
	Version   string
	Labels    string
	FlagTree  blackduck.FlagTree
}

// WaitUntilReady ...
func (t BlackDuckTester) WaitUntilReady() {
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
func (t BlackDuckTester) Verify() error {
	checks := []func() error{
		t.checkPersistentStorageExists,
		t.checkExposedService,
		t.checkSecurityContexts,
		t.checkBinaryAnalysis,
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

func (t BlackDuckTester) getPodIDHelper(podName string) string {
	// podName format: <name>-blackduck-<podname>
	// podID format: blackduck-<podname>
	rePattern := fmt.Sprintf("%s-(blackduck-[a-z]+[-a-z]*)-[0-9]+", t.Name)
	r, _ := regexp.Compile(rePattern)
	matches := r.FindStringSubmatch(podName)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func (t BlackDuckTester) podWithNameExists(podName, namespace string) bool {
	targetPoID := podName

	found := false

	podList, err := util.ListPodsWithLabels(KubeClient, namespace, "")
	if err != nil {
		return false
	}
	for _, po := range podList.Items {
		poID := t.getPodIDHelper(po.Name)
		if poID == targetPoID {
			found = true
			break
		}
	}

	return found
}

func (t BlackDuckTester) checkPersistentStorageExists() error {
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

func (t BlackDuckTester) checkBinaryAnalysis() error {
	binaryScannerPoID := "blackduck-binaryscanner"
	rabbitmqPoID := "blackduck-rabbitmq"

	foundBinaryScanner := t.podWithNameExists(binaryScannerPoID, t.Namespace)
	foundRabbitMQ := t.podWithNameExists(rabbitmqPoID, t.Namespace)

	if foundBinaryScanner != t.FlagTree.EnableBinaryAnalysis {
		return fmt.Errorf("enableBinaryAnalysis is %+v but foundBinaryScanner='%+v'", t.FlagTree.EnableBinaryAnalysis, foundBinaryScanner)
	}
	if t.FlagTree.EnableBinaryAnalysis && !foundRabbitMQ {
		return fmt.Errorf("enableBinaryAnalysis is %+v but didn't find RabbitMQ", t.FlagTree.EnableBinaryAnalysis)
	}
	return nil
}

func (t BlackDuckTester) checkExposedService() error {
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

func podIDToPodSecurityContextIDHelper(podID string) string {
	podIDToPodSecurityContextID := map[string]string{
		"blackduck-postgres":        "blackduck-postgres",
		"blackduck-authentication":  "blackduck-authentication",
		"blackduck-cfssl":           "blackduck-cfssl",
		"blackduck-documentation":   "blackduck-documentation",
		"blackduck-jobrunner":       "blackduck-jobrunner",
		"blackduck-rabbitmq":        "blackduck-rabbitmq",
		"blackduck-registration":    "blackduck-registration",
		"blackduck-scan":            "blackduck-scan",
		"blackduck-uploadcache":     "blackduck-uploadcache",
		"blackduck-webapp-logstash": "blackduck-webapp",
		"blackduck-webserver":       "blackduck-nginx",
		"blackduck-binaryscanner":   "appcheck-worker",
	}
	if val, ok := podIDToPodSecurityContextID[podID]; ok {
		return val
	}
	return ""
}

func podIDToSecurityContextIDsHelper(podID string) []string {
	podIDToSecurityContextIDs := map[string][]string{
		"blackduck-init":            {"blackduck-init"},
		"blackduck-webapp-logstash": {"blackduck-logstash"},
	}
	if val, ok := podIDToSecurityContextIDs[podID]; ok {
		return val
	}
	return []string{}
}

func (t BlackDuckTester) checkSecurityContexts() error {
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
		poID := t.getPodIDHelper(po.Name)
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
		pscID := podIDToPodSecurityContextIDHelper(poID)
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
			scIDs := podIDToSecurityContextIDsHelper(poID)

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
