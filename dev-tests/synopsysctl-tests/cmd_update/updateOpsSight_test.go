package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestUpdateOpsSight_EnableMetrics ...
func TestUpdateOpsSight_EnableMetrics(t *testing.T) {
	opsSightTester := tu.NewOpsSightTester()
	opsSightTester.FlagTree.EnableMetrics = "FALSE"

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
	fmt.Printf("Update OpsSight\n")
	_, err = tu.Synospysctl("update opssight %s -n %s --enable-metrics false", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	opsSightTester.WaitUntilReady()

	err = opsSightTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
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
