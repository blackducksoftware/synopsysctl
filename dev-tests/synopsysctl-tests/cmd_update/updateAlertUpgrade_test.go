package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestUpgradeAlert ...
func TestUpgradeAlert(t *testing.T) {
	alertTester := tu.NewAlertTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Alert v5.3.1\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version 5.3.1 --postgres-password pass", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	// Test
	fmt.Printf("Upgrade Alert to v%s\n", alertTester.Version)
	_, err = tu.Synospysctl("update alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	fmt.Printf("Verifying Alert Configuration\n")
	err = alertTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
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
