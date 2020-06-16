package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestUpgradeBlackDuck ...
func TestUpgradeBlackDuck(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Creating Black Duck v2020.4.0\n")
	_, err = tu.Synospysctl("create blackduck %s -n %s --version 2020.4.0 --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	blackDuckTester.WaitUntilReady()

	// Test
	fmt.Printf("Upgrade Black Duck to v%s\n", blackDuckTester.Version)
	_, err = tu.Synospysctl("update blackduck %s -n %s --version %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	blackDuckTester.WaitUntilReady()

	fmt.Printf("Verifying Black Duck Configuration\n")
	err = blackDuckTester.Verify()
	if err != nil {
		t.Errorf("%s", err)
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
