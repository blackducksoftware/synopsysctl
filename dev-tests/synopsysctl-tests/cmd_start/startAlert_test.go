package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestStartAlert ...
func TestStartAlert(t *testing.T) {
	alertTester := tu.NewAlertTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

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

	// Test
	fmt.Printf("Starting Alert\n")
	_, err = tu.Synospysctl("start alert %s -n %s", alertTester.Name, alertTester.Namespace)
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
		return
	}
}
