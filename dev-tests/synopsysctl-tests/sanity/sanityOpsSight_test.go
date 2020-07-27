package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestSanityOpsSight ...
func TestSanityOpsSight(t *testing.T) {
	opsSightTester := tu.NewOpsSightTester()

	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating OpsSight\n")
	_, err = tu.Synospysctl("create opssight %s -n %s --version %s", opsSightTester.Name, opsSightTester.Namespace, opsSightTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating OpsSight Native\n")
	_, err = tu.Synospysctl("create opssight native %s -n %s --version %s", opsSightTester.Name, opsSightTester.Namespace, opsSightTester.Version)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Getting OpsSight\n")
	_, err = tu.Synospysctl("get opssight %s -n %s", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Updating OpsSight\n")
	_, err = tu.Synospysctl("update opssight %s -n %s --enable-pod-processor=true", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Stopping OpsSight\n")
	_, err = tu.Synospysctl("stop opssight %s -n %s", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Starting OpsSight\n")
	_, err = tu.Synospysctl("start opssight %s -n %s", opsSightTester.Name, opsSightTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

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
