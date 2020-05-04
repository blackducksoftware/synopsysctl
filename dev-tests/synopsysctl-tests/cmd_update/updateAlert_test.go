package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestUpdateAlert_ChangeNodePortToLoadBalancer ...
func TestUpdateAlert_ChangeNodePortToLoadBalancer(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.ExposeService = "LOADBALANCER"

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	// Test
	fmt.Printf("Update Alert\n")
	_, err = tu.Synospysctl("update alert %s -n %s --expose-ui LOADBALANCER", alertTester.Name, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

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

// TestUpdateAlert_AddSecurityContexts ...
func TestUpdateAlert_AddSecurityContexts(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.SecurityContextFilePath = tu.GetAlertSecurityContextsPath1()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	// Test
	fmt.Printf("Update Alert\n")
	_, err = tu.Synospysctl("update alert %s -n %s --security-context-file-path %s", alertTester.Name, alertTester.Namespace, alertTester.FlagTree.SecurityContextFilePath)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

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

// TestUpdateAlert_ChangeSecurityContexts ...
func TestUpdateAlert_ChangeSecurityContexts(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.SecurityContextFilePath = tu.GetAlertSecurityContextsPath2()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s --security-context-file-path %s", alertTester.Name, alertTester.Namespace, alertTester.Version, tu.GetAlertSecurityContextsPath1())
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

	// Test
	fmt.Printf("Update Alert\n")
	_, err = tu.Synospysctl("update alert %s -n %s --security-context-file-path %s", alertTester.Name, alertTester.Namespace, alertTester.FlagTree.SecurityContextFilePath)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	alertTester.WaitUntilReady()

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
