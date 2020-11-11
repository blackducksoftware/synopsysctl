package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestStopAlert ...
func TestStopAlert(t *testing.T) {
	alertTester := tu.NewAlertTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s --postgres-password pass", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	alertTester.WaitUntilReady()

	// Test
	fmt.Printf("Stopping Alert\n")
	_, err = tu.Synospysctl("stop alert %s -n %s", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	err = util.WaitForPodsToBeDeletedOrComplete(tu.KubeClient, alertTester.Namespace, alertTester.Labels)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Tear Down
	fmt.Printf("Deleting Alert\n")
	_, err = tu.Synospysctl("delete alert %s -n %s", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}
