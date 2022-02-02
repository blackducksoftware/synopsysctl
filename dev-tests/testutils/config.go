package testutils

import (
	// get auth clients for gcp
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"

	"github.com/blackducksoftware/synopsysctl/pkg/util"
)

// TestConfig ...
var TestConfig = LoadTestConfig()

// AlertTestConfig ...
type AlertTestConfig struct {
	Version          string `json:"version"`
	AppResourcesPath string `json:"appResourcesPath"`
}

// BDBATestConfig ...
type BDBATestConfig struct {
	Version          string `json:"version"`
	AppResourcesPath string `json:"appResourcesPath"`
}

// BlackDuckTestConfig ...
type BlackDuckTestConfig struct {
	Version          string `json:"version"`
	AppResourcesPath string `json:"appResourcesPath"`
	Registry         string `json:"registry"`
	TLSCertPath      string `json:"tlsCertPath"`
	TLSKeyPath       string `json:"tlsKeyPath"`
}

// OpsSightTestConfig ...
type OpsSightTestConfig struct {
	Version          string `json:"version"`
	AppResourcesPath string `json:"appResourcesPath"`
}

// TestConfigStruct ...
type TestConfigStruct struct {
	// Config
	AbsolutePathToTestSuite string `json:"absolutePathToTestSuite"`

	// Synopsysctl
	SynopsysctlPath string `json:"synopsysctlPath"`

	// App Configs
	Alert     AlertTestConfig     `json:"alert"`
	BDBA      BDBATestConfig      `json:"bdba"`
	BlackDuck BlackDuckTestConfig `json:"blackDuck"`
	OpsSight  OpsSightTestConfig  `json:"opsSight"`
}

// LoadTestConfig ...
func LoadTestConfig() TestConfigStruct {
	tc := TestConfigStruct{}
	// TODO - make this better
	for _, pth := range []string{"../", "../../", "../../../", "../../../../", "../../../../../"} {
		configFilePath := fmt.Sprintf("%sconfig.json", pth)
		data, err := util.ReadFileData(configFilePath)
		if err != nil {
			continue
		}

		err = json.Unmarshal([]byte(data), &tc)
		if err != nil {
			log.Fatalf("failed to unmarshal test config: %+v", err)
		}
		absPath, _ := filepath.Abs(pth)
		tc.AbsolutePathToTestSuite = absPath
		return tc
	}
	log.Fatal("failed to read config file")
	return tc
}
