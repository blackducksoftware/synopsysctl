package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestSanityBDBA ...
func TestSanityBDBA(t *testing.T) {
	bdbaTester := tu.NewBDBATester()

	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating BDBA\n")
	_, err = tu.Synospysctl("create bdba -n %s --version %s --license-username user --license-password pass", bdbaTester.Namespace, bdbaTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating BDBA Native\n")
	_, err = tu.Synospysctl("create bdba native -n %s --version %s --license-username user --license-password pass", bdbaTester.Namespace, bdbaTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Getting BDBA\n")
	_, err = tu.Synospysctl("get bdba -n %s", bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Updating BDBA\n")
	_, err = tu.Synospysctl("update bdba -n %s --license-username user --license-password pass --ingress-host mock-host", bdbaTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

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
	}
}
