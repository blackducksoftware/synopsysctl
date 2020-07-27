package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestStopOpsSight ...
func TestStopOpsSight(t *testing.T) {
	opsSightTester := tu.NewOpsSightTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating OpsSight\n")
	_, err = tu.Synospysctl("create opssight %s -n %s --version %s", opsSightTester.Name, opsSightTester.Namespace, opsSightTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	opsSightTester.WaitUntilReady()

	// Test
	fmt.Printf("Stopping OpsSight\n")
	_, err = tu.Synospysctl("stop opssight %s -n %s", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	err = util.WaitForPodsToBeDeletedOrComplete(tu.KubeClient, opsSightTester.Namespace, opsSightTester.Labels)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Tear Down
	fmt.Printf("Deleting OpsSight\n")
	_, err = tu.Synospysctl("delete opssight %s -n %s", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}
