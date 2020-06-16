package testutils

import (
	"log"

	"github.com/blackducksoftware/synopsysctl/pkg/polaris"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// GetLatestPolarisVersion ...
func GetLatestPolarisVersion() string {
	if TestConfig.Polaris.Version != "" {
		return TestConfig.Polaris.Version
	}
	return "2020.03"
}

// NewPolarisTester ...
func NewPolarisTester() *PolarisTester {
	t := PolarisTester{
		AppName: "polaris",
	}
	// Get default values for an Polaris-Reporting test
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestPolarisVersion()
	t.Labels = ""

	// Config for Polaris Reporting
	t.FlagTree = polaris.FlagTree{}
	return &t
}

// PolarisTester ...
type PolarisTester struct {
	AppName   string
	Namespace string
	Version   string
	Labels    string
	FlagTree  polaris.FlagTree
}

// WaitUntilReady ...
func (t PolarisTester) WaitUntilReady() {
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
func (t PolarisTester) Verify() error {
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

func (t PolarisTester) checkSomething() error {
	return nil
}
