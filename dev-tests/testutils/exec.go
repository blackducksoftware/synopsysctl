package testutils

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	// get auth clients for gcp
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// FlagWasSet ...
func FlagWasSet(flagArgs []string, flagName string) bool {
	re := regexp.MustCompile(flagName)
	found := false
	for _, arg := range flagArgs {
		if re.MatchString(arg) {
			found = true
			break
		}
	}
	return found
}

// SetAppResourcesPath ...
func SetAppResourcesPath(flagArgs []string) []string {
	if len(flagArgs) > 2 {
		mainCmd := flagArgs[0]
		app := flagArgs[1]
		if mainCmd == "create" || mainCmd == "update" || mainCmd == "stop" || mainCmd == "start" {
			resourcesPath := ""
			switch strings.ToUpper(app) {
			case "ALERT":
				resourcesPath = TestConfig.Alert.AppResourcesPath
			case "BDBA":
				resourcesPath = TestConfig.BDBA.AppResourcesPath
			case "BLACKDUCK":
				resourcesPath = TestConfig.BlackDuck.AppResourcesPath
			case "OPSSIGHT":
				resourcesPath = TestConfig.OpsSight.AppResourcesPath
			}
			if resourcesPath != "" && !FlagWasSet(flagArgs, "--app-resources-path") {
				flagArgs = append(flagArgs, fmt.Sprintf("--app-resources-path=%s", resourcesPath))
			}
		}
	}
	return flagArgs
}

// SetBlackDuckRegistry ...
func SetBlackDuckRegistry(flagArgs []string) []string {
	if len(flagArgs) > 2 {
		mainCmd := flagArgs[0]
		app := flagArgs[1]
		if mainCmd == "create" || mainCmd == "update" {
			registry := ""
			switch strings.ToUpper(app) {
			case "BLACKDUCK":
				registry = TestConfig.BlackDuck.Registry
			}
			if registry != "" && !FlagWasSet(flagArgs, "--registry") {
				flagArgs = append(flagArgs, fmt.Sprintf("--registry=%s", registry))
			}
		}
	}
	return flagArgs
}

// Synospysctl ...
func Synospysctl(cmdString string, args ...interface{}) (string, error) {
	fullCmdString := fmt.Sprintf(cmdString, args...)
	cmdValues := strings.Fields(fullCmdString)
	cmdValues = SetAppResourcesPath(cmdValues)
	cmdValues = SetBlackDuckRegistry(cmdValues)
	cmdValues = append([]string{TestConfig.SynopsysctlPath}, cmdValues...)
	return ExecCmd(cmdValues...)
}

// Helm ...
func Helm(cmdString string, args ...interface{}) (string, error) {
	fullCmdString := fmt.Sprintf(cmdString, args...)
	cmdValues := strings.Fields(fullCmdString)
	cmdValues = append([]string{"helm"}, cmdValues...)
	return ExecCmd(cmdValues...)
}

//ExecCmd ...
func ExecCmd(args ...string) (string, error) {
	fmt.Printf("\033[2m >> %s\033[0m\n", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	stdoutErr, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s [%+v]", string(stdoutErr), err)
	}
	return string(stdoutErr), nil
}
