package createtests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestCreateBDBA_Default ...
func TestCreateBDBA_Default(t *testing.T) {
	bdbaTester := tu.NewBDBATester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating BDBA\n")
	_, err = tu.Synospysctl("create bdba -n %s --version %s --license-username user --license-password pass", bdbaTester.Namespace, bdbaTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	bdbaTester.WaitUntilReady()

	fmt.Printf("Verifying BDBA Configuration\n")
	err = bdbaTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Tear Down
	fmt.Printf("Deleting BDBA\n")
	_, err = tu.Synospysctl("delete bdba -n %s", bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
}
