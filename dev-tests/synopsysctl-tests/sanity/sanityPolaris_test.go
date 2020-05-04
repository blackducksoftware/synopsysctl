package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestSanityPolaris ...
func TestSanityPolaris(t *testing.T) {
	polarisTester := tu.NewPolarisTester()

	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, polarisTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating Polaris\n")
	_, err = tu.Synospysctl("create polaris -n %s --version %s --smtp-host host --smtp-port 1234 --smtp-username user --smtp-password pass --smtp-sender-email my@email.com", polarisTester.Namespace, polarisTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating Polaris Native\n")
	_, err = tu.Synospysctl("create polaris native -n %s --version %s --smtp-host host --smtp-port 1234 --smtp-username user --smtp-password pass --smtp-sender-email my@email.com", polarisTester.Namespace, polarisTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Getting Polaris\n")
	_, err = tu.Synospysctl("get polaris -n %s", polarisTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Updating Polaris\n")
	_, err = tu.Synospysctl("update polaris -n %s --enable-reporting=true", polarisTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Polaris\n")
	_, err = tu.Synospysctl("delete polaris -n %s", polarisTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, polarisTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}
