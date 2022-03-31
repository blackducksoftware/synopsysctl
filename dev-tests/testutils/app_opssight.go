package testutils

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/opssight"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// GetLatestOpsSightVersion ...
func GetLatestOpsSightVersion() string {
	if TestConfig.OpsSight.Version != "" {
		return TestConfig.OpsSight.Version
	}
	return "2.2.5"
}

// NewOpsSightTester ...
func NewOpsSightTester() *OpsSightTester {
	t := OpsSightTester{
		AppName: util.OpsSightName,
	}
	// Get default values for an OpsSight test
	t.Name = GenName(t.AppName)
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestOpsSightVersion()
	t.Labels = ""

	// Config for OpsSight
	t.FlagTree = opssight.FlagTree{}
	t.FlagTree.EnableMetrics = "TRUE"
	t.FlagTree.PerceiverEnablePodPerceiver = "TRUE"
	t.FlagTree.PerceiverEnableImagePerceiver = "FALSE"
	t.FlagTree.PerceiverEnableQuayPerceiver = "FALSE"
	t.FlagTree.PerceiverEnableArtifactoryPerceiver = "FALSE"
	return &t
}

// OpsSightTester ...
type OpsSightTester struct {
	AppName   string
	Name      string
	Namespace string
	Version   string
	Labels    string
	FlagTree  opssight.FlagTree
}

// WaitUntilReady ...
func (t OpsSightTester) WaitUntilReady() {
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
func (t OpsSightTester) Verify() error {
	checks := []func() error{
		t.checkPrometheusEnabled,
		t.checkPodProcessorEnabled,
		t.checkImageProcessorEnabled,
		t.checkQuayProcessorEnabled,
		t.checkArtifactoryProcessorEnabled,
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

func (t OpsSightTester) getIDHelper(rtoName string) string {
	// rtoName format: <name>-opssight-<resourcename>-12345678 || <name>-opssight-<resourcename>
	// ID format: opssight-<resourcename>
	rePattern := fmt.Sprintf("%s-(opssight-[a-z]+[-a-z]*[a-z])(-[0-9]+)*", t.Name)
	r, _ := regexp.Compile(rePattern)
	matches := r.FindStringSubmatch(rtoName)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func (t OpsSightTester) deploymentWithNameExists(deploymentName, namespace string) bool {
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

func (t OpsSightTester) serviceWithNameExists(serviceName, namespace string) bool {
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

func (t OpsSightTester) configMapWithNameExists(configMapName, namespace string) bool {
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

func (t OpsSightTester) serviceAccountWithNameExists(serviceAccountName, namespace string) bool {
	targetServiceAccountID := serviceAccountName

	found := false

	serviceAccountList, err := util.ListServiceAccounts(KubeClient, namespace, "")
	if err != nil {
		return false
	}
	for _, sa := range serviceAccountList.Items {
		serviceAccountID := t.getIDHelper(sa.Name)
		if serviceAccountID == targetServiceAccountID {
			found = true
			break
		}
	}
	return found
}

func (t OpsSightTester) clusterRoleBindingWithNameExists(clusterRoleBindingName string) bool {
	targetClusterRoleBindingID := clusterRoleBindingName

	found := false

	clusterRoleBindingsList, err := util.ListClusterRoleBindings(KubeClient, "")
	if err != nil {
		return false
	}
	for _, crb := range clusterRoleBindingsList.Items {
		clusterRoleBindingID := t.getIDHelper(crb.Name)
		if clusterRoleBindingID == targetClusterRoleBindingID {
			found = true
			break
		}
	}
	return found
}

func (t OpsSightTester) clusterRoleWithNameExists(clusterRoleName string) bool {
	targetClusterRoleID := clusterRoleName

	found := false

	clusterRoleList, err := util.ListClusterRoles(KubeClient, "")
	if err != nil {
		return false
	}
	for _, cr := range clusterRoleList.Items {
		clusterRoleID := t.getIDHelper(cr.Name)
		if clusterRoleID == targetClusterRoleID {
			found = true
			break
		}
	}
	return found
}

func (t OpsSightTester) checkPrometheusEnabled() error {
	// Verify Deployment <name>-opssight-prometheus
	foundDeployment := t.deploymentWithNameExists("opssight-prometheus", t.Namespace)
	if strings.ToUpper(t.FlagTree.EnableMetrics) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("EnableMetrics is '%+v' but foundDeployment='%+v'", t.FlagTree.EnableMetrics, foundDeployment)
	}

	// Verify Service <name>-opssight-prometheus
	foundMetricsService := t.serviceWithNameExists("opssight-prometheus", t.Namespace)
	if strings.ToUpper(t.FlagTree.EnableMetrics) != strings.ToUpper(strconv.FormatBool(foundMetricsService)) {
		return fmt.Errorf("EnableMetrics is '%+v' but foundMetricsService='%+v'", t.FlagTree.EnableMetrics, foundMetricsService)
	}

	// Verify ConfigMap <name>-opssight-prometheus
	foundMetricsConfigMap := t.configMapWithNameExists("opssight-prometheus", t.Namespace)
	if strings.ToUpper(t.FlagTree.EnableMetrics) != strings.ToUpper(strconv.FormatBool(foundMetricsConfigMap)) {
		return fmt.Errorf("EnableMetrics is '%+v' but foundMetricsConfigMap='%+v'", t.FlagTree.EnableMetrics, foundMetricsConfigMap)
	}

	return nil
}

func (t OpsSightTester) checkPodProcessorEnabled() error {
	// Verify Deployment <name>-opssight-pod-processor
	foundDeployment := t.deploymentWithNameExists("opssight-pod-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnablePodPerceiver) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("PerceiverEnablePodPerceiver is '%+v' but foundDeployment='%+v'", t.FlagTree.PerceiverEnablePodPerceiver, foundDeployment)
	}

	// Verify Service <name>-opssight-pod-processor
	foundService := t.serviceWithNameExists("opssight-pod-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnablePodPerceiver) != strings.ToUpper(strconv.FormatBool(foundService)) {
		return fmt.Errorf("PerceiverEnablePodPerceiver is '%+v' but foundService='%+v'", t.FlagTree.PerceiverEnablePodPerceiver, foundService)
	}

	// Verify Service Account <name>-opssight-pod-processor
	foundServiceAccount := t.serviceAccountWithNameExists("opssight-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnablePodPerceiver) != strings.ToUpper(strconv.FormatBool(foundServiceAccount)) {
		return fmt.Errorf("PerceiverEnablePodPerceiver is '%+v' but foundServiceAccount='%+v'", t.FlagTree.PerceiverEnablePodPerceiver, foundServiceAccount)
	}

	// Verify Cluster Role <name>-opssight-pod-processor
	foundClusterRole := t.clusterRoleWithNameExists("opssight-pod-processor")
	if strings.ToUpper(t.FlagTree.PerceiverEnablePodPerceiver) != strings.ToUpper(strconv.FormatBool(foundClusterRole)) {
		return fmt.Errorf("PerceiverEnablePodPerceiver is '%+v' but foundClusterRole='%+v'", t.FlagTree.PerceiverEnablePodPerceiver, foundClusterRole)
	}

	return nil
}

func (t OpsSightTester) checkImageProcessorEnabled() error {
	// Verify Deployment <name>-opssight-image-processor
	foundDeployment := t.deploymentWithNameExists("opssight-image-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableImagePerceiver) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("PerceiverEnableImagePerceiver is '%+v' but foundDeployment='%+v'", t.FlagTree.PerceiverEnableImagePerceiver, foundDeployment)
	}

	// Verify Service <name>-opssight-image-processor
	foundService := t.serviceWithNameExists("opssight-image-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableImagePerceiver) != strings.ToUpper(strconv.FormatBool(foundService)) {
		return fmt.Errorf("PerceiverEnableImagePerceiver is '%+v' but foundService='%+v'", t.FlagTree.PerceiverEnableImagePerceiver, foundService)
	}

	// Verify Cluster Role Binding <name>-opssight-image-processor
	foundServiceAccount := t.clusterRoleBindingWithNameExists("opssight-image-processor")
	if strings.ToUpper(t.FlagTree.PerceiverEnableImagePerceiver) != strings.ToUpper(strconv.FormatBool(foundServiceAccount)) {
		return fmt.Errorf("PerceiverEnableImagePerceiver is '%+v' but foundServiceAccount='%+v'", t.FlagTree.PerceiverEnableImagePerceiver, foundServiceAccount)
	}

	// Verify Cluster Role <name>-opssight-image-processor
	foundClusterRole := t.clusterRoleWithNameExists("opssight-image-processor")
	if strings.ToUpper(t.FlagTree.PerceiverEnableImagePerceiver) != strings.ToUpper(strconv.FormatBool(foundClusterRole)) {
		return fmt.Errorf("PerceiverEnableImagePerceiver is '%+v' but foundClusterRole='%+v'", t.FlagTree.PerceiverEnableImagePerceiver, foundClusterRole)
	}

	return nil
}

func (t OpsSightTester) checkQuayProcessorEnabled() error {
	// Verify Deployment <name>-opssight-quay-processor
	foundDeployment := t.deploymentWithNameExists("opssight-quay-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableQuayPerceiver) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("PerceiverEnableQuayPerceiver is '%+v' but foundDeployment='%+v'", t.FlagTree.PerceiverEnableQuayPerceiver, foundDeployment)
	}

	// Verify Service <name>-opssight-quay-processor
	foundService := t.serviceWithNameExists("opssight-quay-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableQuayPerceiver) != strings.ToUpper(strconv.FormatBool(foundService)) {
		return fmt.Errorf("PerceiverEnableQuayPerceiver is '%+v' but foundService='%+v'", t.FlagTree.PerceiverEnableQuayPerceiver, foundService)
	}

	return nil
}

func (t OpsSightTester) checkArtifactoryProcessorEnabled() error {
	// Verify Deployment <name>-opssight-artifactory-processor
	foundDeployment := t.deploymentWithNameExists("opssight-artifactory-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableArtifactoryPerceiver) != strings.ToUpper(strconv.FormatBool(foundDeployment)) {
		return fmt.Errorf("PerceiverEnableArtifactoryPerceiver is '%+v' but foundDeployment='%+v'", t.FlagTree.PerceiverEnableArtifactoryPerceiver, foundDeployment)
	}

	// Verify Service <name>-opssight-artifactory-processor
	foundService := t.serviceWithNameExists("opssight-artifactory-processor", t.Namespace)
	if strings.ToUpper(t.FlagTree.PerceiverEnableArtifactoryPerceiver) != strings.ToUpper(strconv.FormatBool(foundService)) {
		return fmt.Errorf("PerceiverEnableArtifactoryPerceiver is '%+v' but foundService='%+v'", t.FlagTree.PerceiverEnableArtifactoryPerceiver, foundService)
	}

	return nil
}
