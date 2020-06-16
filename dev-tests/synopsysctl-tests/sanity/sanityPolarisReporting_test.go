package sanitytests

import (
	"fmt"
	"testing"

	tu "github.com/blackducksoftware/synopsysctl/dev-tests/testutils"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestSanityPolarisReporting ...
func TestSanityPolarisReporting(t *testing.T) {
	polarisReportingTester := tu.NewPolarisReportingTester()

	fmt.Printf("Creating Namespace\n")
	_, err := util.CreateNamespace(tu.KubeClient, polarisReportingTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating PolarisReporting\n")
	_, err = tu.Synospysctl("create polaris-reporting -n %s --version %s --enable-postgres-container=true --fqdn domain --gcp-service-account-path %s --storage-class sc --smtp-host host --smtp-port 1234 --smtp-username user --smtp-password pass --smtp-sender-email my@email.com --postgres-password pass", polarisReportingTester.Namespace, polarisReportingTester.Version, tu.GetPolarisReportingServiceAccountPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Creating PolarisReporting Native\n")
	_, err = tu.Synospysctl("create polaris-reporting native -n %s --version %s --enable-postgres-container=true --fqdn domain --gcp-service-account-path %s --storage-class sc --smtp-host host --smtp-port 1234 --smtp-username user --smtp-password pass --smtp-sender-email my@email.com --postgres-password pass", polarisReportingTester.Namespace, polarisReportingTester.Version, tu.GetPolarisReportingServiceAccountPath())
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Getting PolarisReporting\n")
	_, err = tu.Synospysctl("get polaris-reporting -n %s", polarisReportingTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Updating PolarisReporting\n")
	_, err = tu.Synospysctl("update polaris-reporting -n %s --postgres-port 1234", polarisReportingTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting PolarisReporting\n")
	_, err = tu.Synospysctl("delete polaris-reporting -n %s", polarisReportingTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	fmt.Printf("Deleting Namespace\n")
	err = util.DeleteNamespace(tu.KubeClient, polarisReportingTester.Namespace)
	if err != nil {
		t.Errorf("%s", err)
	}
}
