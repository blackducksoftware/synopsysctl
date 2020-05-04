package createtests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestCreateAlert_Default ...
func TestCreateAlert_Default(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.ExposeService = "LOADBALANCER"

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	path1 := "https://sig-repo.synopsys.com/sig-cloudnative/synopsys-alert-5.3.2.tgz"

	// Test
	fmt.Printf("Creating Alert 5.3.2\n")
	_, err = tu.Helm("install %s %s -n %s --set exposedServiceType=LoadBalancer", alertTester.Name, path1, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	fmt.Printf("Verifying Alert Configuration\n")
	err = alertTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Upgrade Alert to 6.0.0\n")
	path2 := "/Users/hammer/go/src/github.com/blackducksoftware/blackduck-alert/deployment/helm/synopsys-alert"
	_, err = tu.Helm("upgrade %s %s -n %s", alertTester.Name, path2, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	fmt.Printf("Verifying Alert Configuration\n")
	err = alertTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Tear Down
	fmt.Printf("Uninstall Alert\n")
	_, err = tu.Helm("uninstall %s -n %s", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
}
