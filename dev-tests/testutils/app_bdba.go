package testutils

import (
	"log"

	"github.com/blackducksoftware/synopsysctl/pkg/bdba"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// GetLatestBDBAVersion ...
func GetLatestBDBAVersion() string {
	if TestConfig.BDBA.Version != "" {
		return TestConfig.BDBA.Version
	}
	return "2020.03"
}

// NewBDBATester ...
func NewBDBATester() *BDBATester {
	t := BDBATester{
		AppName: "bdba",
	}
	// Get default values for a BDBA test
	t.Namespace = CreateUniqueNamespace(t.AppName)
	t.Version = GetLatestBDBAVersion()
	t.Labels = ""

	// Config for BDBA
	t.FlagTree = bdba.FlagTree{}
	return &t
}

// BDBATester ...
type BDBATester struct {
	AppName   string
	Namespace string
	Version   string
	Labels    string
	FlagTree  bdba.FlagTree
}

// WaitUntilReady ...
func (t BDBATester) WaitUntilReady() {
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
func (t BDBATester) Verify() error {
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

func (t BDBATester) checkSomething() error {
	return nil
}
