package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestMigrateAlert ...
func TestMigrateAlert(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.ExposeService = "NONE" // Operator doesn't expose UI by default

	// Set Up
	fmt.Printf("Deploying Synopsys Operator\n")
	_, err := tu.SynopsysctlOperator("deploy --cluster-scoped --enable-blackduck --enable-alert")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForPodsToAppear(tu.KubeClient, "synopsys-operator", "")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForPodsToBeRunningOrComplete(tu.KubeClient, "synopsys-operator", "")
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating Alert with Synopsys Operator\n")
	_, err = tu.SynopsysctlOperator("create alert %s -n %s --persistent-storage=true --standalone=true", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForMoreThanNPods(tu.KubeClient, alertTester.Namespace, "", 1)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForPodsToBeRunningOrComplete(tu.KubeClient, alertTester.Namespace, "")
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Test
	fmt.Printf("Migrating Alert\n")
	_, err = tu.Synospysctl("update alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Wait until Alert is Running\n")
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

	fmt.Printf("Deleting Alert Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Deleting Synopsys Operator Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, "synopsys-operator")
	if err != nil {
		t.Errorf("%s", err)
	}
}
