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

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s", alertTester.Name, alertTester.Namespace, alertTester.Version)
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

// TestCreateAlert ...
func TestCreateAlert_NotStadnalone_NoPersistentStorage_LoadBalancer(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.StandAlone = "False"
	alertTester.FlagTree.PersistentStorage = "False"
	alertTester.FlagTree.ExposeService = "LOADBALANCER"

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s --standalone=false --persistent-storage=false --expose-ui=LOADBALANCER", alertTester.Name, alertTester.Namespace, alertTester.Version)
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

// TestCreateAlert_SecurityContexts ...
func TestCreateAlert_SecurityContexts(t *testing.T) {
	alertTester := tu.NewAlertTester()
	alertTester.FlagTree.SecurityContextFilePath = tu.GetAlertSecurityContextsPath1()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, alertTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Alert\n")
	_, err = tu.Synospysctl("create alert %s -n %s --version %s --security-context-file-path %s", alertTester.Name, alertTester.Namespace, alertTester.Version, alertTester.FlagTree.SecurityContextFilePath)
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
