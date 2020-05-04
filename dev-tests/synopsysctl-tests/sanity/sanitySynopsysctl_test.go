package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
)

// TestCrudAlertSanity ...
func TestSynopsysctlHelp(t *testing.T) {
	fmt.Printf("synopsysctl --version\n")
	v, err := tu.Synospysctl("--help")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
	fmt.Printf("%+v", v)

	fmt.Printf("synopsysctl --help\n")
	_, err = tu.Synospysctl("--help")
	if err != nil {
		t.Errorf("%s", err)
		return
	}
}
