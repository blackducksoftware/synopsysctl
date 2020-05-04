package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestMigrateBlackDuck ...
func TestMigrateBlackDuck(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()
	blackDuckTester.FlagTree.ExposeService = "NONE" // Operator doesn't expose UI by default

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

	fmt.Printf("Creating Black Duck with Synopsys Operator\n")
	_, err = tu.SynopsysctlOperator("create blackduck %s -n %s --admin-password pass --user-password pass --postgres-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForMoreThanNPods(tu.KubeClient, blackDuckTester.Namespace, "", 4)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForPodsToBeRunningOrComplete(tu.KubeClient, blackDuckTester.Namespace, "")
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Test
	fmt.Printf("Migrating Black Duck\n")
	_, err = tu.Synospysctl("update blackduck %s -n %s --version %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Wait until Black Duck is Ready\n")
	blackDuckTester.WaitUntilReady()

	fmt.Printf("Verifying Black Duck Configuration\n")
	err = blackDuckTester.Verify()
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

	fmt.Printf("Deleting Black Duck Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Deleting Synopsys Operator Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, "synopsys-operator")
	if err != nil {
		t.Errorf("%s", err)
	}
}

// TestMigrateBlackDuck_EmptyRegistry ...
func TestMigrateBlackDuck_EmptyRegistry(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()
	blackDuckTester.FlagTree.ExposeService = "NONE" // Operator doesn't expose UI by default

	// Set Up
	fmt.Printf("Deploying Synopsys Operator\n")
	_, err := tu.SynopsysctlOperator("deploy --cluster-scoped --enable-blackduck")
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

	fmt.Printf("Creating Black Duck with Synopsys Operator\n")
	_, err = tu.SynopsysctlOperator("create blackduck %s -n %s --admin-password pass --user-password pass --postgres-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s --pull-secret-name=testSecretName", blackDuckTester.Name, blackDuckTester.Namespace, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForMoreThanNPods(tu.KubeClient, blackDuckTester.Namespace, "", 4)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	err = util.WaitForPodsToBeRunningOrComplete(tu.KubeClient, blackDuckTester.Namespace, "")
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	// Test
	fmt.Printf("Migrating Black Duck\n")
	_, err = tu.Synospysctl("update blackduck %s -n %s --version %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Wait until Black Duck is Ready\n")
	blackDuckTester.WaitUntilReady()

	fmt.Printf("Verifying Black Duck Configuration\n")
	err = blackDuckTester.Verify()
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

	fmt.Printf("Deleting Black Duck Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	fmt.Printf("Deleting Synopsys Operator Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, "synopsys-operator")
	if err != nil {
		t.Errorf("%s", err)
	}
}
