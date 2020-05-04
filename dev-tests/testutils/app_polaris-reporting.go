package testutils

import (
	"log"

	reporting "github.com/blackducksoftware/synopsysctl/pkg/polaris-reporting"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// GetLatestPolarisReportingVersion ...
func GetLatestPolarisReportingVersion() string {
	if TestConfig.PolarisReporting.Version != "" {
		return TestConfig.PolarisReporting.Version
	}
	return "2020.04"
}

// GetPolarisReportingServiceAccountPath ...
func GetPolarisReportingServiceAccountPath() string {
	if TestConfig.PolarisReporting.ServiceAccountPath != "" {
		return TestConfig.PolarisReporting.ServiceAccountPath
	}
	return GetMockServiceAccount()
}

// NewPolarisReportingTester ...
func NewPolarisReportingTester() *PolarisReportingTester {
	t := PolarisReportingTester{
		AppName: "polaris-reporting",
	}
	// Get default values for an Polaris-Reporting test
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestPolarisReportingVersion()
	t.Labels = ""

	// Config for Polaris Reporting
	t.FlagTree = reporting.FlagTree{}
	return &t
}

// PolarisReportingTester ...
type PolarisReportingTester struct {
	AppName   string
	Namespace string
	Version   string
	Labels    string
	FlagTree  reporting.FlagTree
}

// WaitUntilReady ...
func (t PolarisReportingTester) WaitUntilReady() {
	err := util.WaitForPodsToAppear(KubeClient, t.Namespace, t.Labels)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	util.WaitForPodsToBeRunningOrComplete(KubeClient, t.Namespace, t.Labels)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	util.WaitForPodsToStopTerminating(KubeClient, t.Namespace)
	if err != nil {
		log.Fatalf("%+v", err)
	}
}

// Verify ...
func (t PolarisReportingTester) Verify() error {
	checks := []func() error{
		t.checkSomething,
	}
	var err error
	for _, check := range checks {
		err = check()
		if err != nil {
			return err
		}
	}
	return nil
}

func (t PolarisReportingTester) checkSomething() error {
	return nil
}
