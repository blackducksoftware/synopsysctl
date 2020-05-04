package createtests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestCreateBlackDuck_Default ...
func TestCreateBlackDuck_Default(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Black Duck\n")
	_, err = tu.Synospysctl("create blackduck %s -n %s --version %s --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
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
		return
	}

}

// TestCreateBlackDuck_SecurityContexts ...
func TestCreateBlackDuck_SecurityContexts(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()
	blackDuckTester.FlagTree.SecurityContextFilePath = tu.GetBlackDuckSecurityContextsPath1()

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Black Duck\n")
	_, err = tu.Synospysctl("create blackduck %s -n %s --version %s --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s --security-context-file-path %s", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath(), blackDuckTester.FlagTree.SecurityContextFilePath)
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
		return
	}
}

// TestCreateBlackDuck_NoPersistentStorage_LoadBalancer_BinaryAnalysis_SourceCodeUpload ...
func TestCreateBlackDuck_NoPersistentStorage_LoadBalancer_BinaryAnalysis_SourceCodeUpload(t *testing.T) {
	blackDuckTester := tu.NewBlackDuckTester()
	blackDuckTester.FlagTree.PersistentStorage = "False"
	blackDuckTester.FlagTree.ExposeService = "LOADBALANCER"
	blackDuckTester.FlagTree.EnableBinaryAnalysis = true
	blackDuckTester.FlagTree.EnableSourceCodeUpload = true

	// Set Up
	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, blackDuckTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Test
	fmt.Printf("Creating Black Duck\n")
	_, err = tu.Synospysctl("create blackduck %s -n %s --version %s --admin-password pass --user-password pass --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path %s --certificate-key-file-path %s --persistent-storage=false --expose-ui LOADBALANCER --enable-binary-analysis=true --enable-source-code-upload=true", blackDuckTester.Name, blackDuckTester.Namespace, blackDuckTester.Version, tu.GetBlackDuckTLSCertPath(), tu.GetBlackDuckTLSKeyPath())
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
		return
	}
}
