package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestStopBlackDuck ...
func TestStopBlackDuck(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Black Duck\n")
	_, err = tu.Synospysctl("create blackduck %s -n %s --version %s --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	blackDuckTester.WaitUntilReady()

	// Test
	fmt.Printf("Stopping Black Duck\n")
	_, err = tu.Synospysctl("stop blackduck %s -n %s", blackDuckTester.Name, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	err = util.WaitForPodsToBeDeletedOrComplete(tu.KubeClient, blackDuckTester.Namespace, blackDuckTester.Labels)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Tear Down
	fmt.Printf("Deleting Black Duck\n")
	_, err = tu.Synospysctl("delete blackduck %s -n %s", blackDuckTester.Name, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}
