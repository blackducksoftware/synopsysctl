package update

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestUdateBlackDuck_LoadBalancer ...
func TestUdateBlackDuck_LoadBalancer(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()
	blackDuckTester.FlagTree.ExposeService = "LOADBALANCER"

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
	fmt.Printf("Update Black Duck\n")
	_, err = tu.Synospysctl("update blackduck %s -n %s --expose-ui LOADBALANCER", blackDuckTester.Name, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}
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

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}

// TestUpdateBlackDuck_SecurityContexts ...
func TestUpdateBlackDuck_SecurityContexts(t *testing.T) {
	fmt.Printf("This Test is Broken Until Black Duck 2020.4.2 is released")
	// blackDuckTester := tu.NewBlackDuckTester()

	// // Set Up
	// fmt.Printf("Creating Namespace\n")
	// _, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	// if err != nil {
	// 	t.Errorf("%s", err)
	// }

	// fmt.Printf("Creating Black Duck\n")
	// _, err = tu.Synospysctl("create blackduck %s -n %s --version %s --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }
	// blackDuckTester.WaitUntilReady()

	// // Test
	// blackDuckTester.FlagTree.SecurityContextFilePath = tu.GetBlackDuckSecurityContextsPath1()
	// fmt.Printf("Update Black Duck to have Security Contexts\n")
	// _, err = tu.Synospysctl("update blackduck %s -n %s --security-context-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.FlagTree.SecurityContextFilePath)
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }
	// blackDuckTester.WaitUntilReady()

	// fmt.Printf("Verifying Black Duck Configuration\n")
	// err = blackDuckTester.Verify()
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }

	// fmt.Printf("Update Black Duck to have *new* Security Contexts\n")
	// blackDuckTester.FlagTree.SecurityContextFilePath = tu.GetBlackDuckSecurityContextsPath2()
	// _, err = tu.Synospysctl("update blackduck %s -n %s --security-context-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.FlagTree.SecurityContextFilePath)
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }
	// blackDuckTester.WaitUntilReady()

	// fmt.Printf("Verifying Black Duck Configuration\n")
	// err = blackDuckTester.Verify()
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }

	// // Tear Down
	// fmt.Printf("Deleting Black Duck\n")
	// _, err = tu.Synospysctl("delete blackduck %s -n %s", blackDuckTester.Name, blackDuckTester.Namespace)
	// if err != nil {
	// 	t.Errorf("%s", err)
	// 	return
	// }

	// fmt.Printf("Deleting Namespace\n")
	// err = util.DeleteNamespace(tu.KubeClient, blackDuckTester.Namespace)
	// if err != nil {
	// 	t.Errorf("%s", err)
	// }
}
