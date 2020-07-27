package testutils

import "fmt"

var testDirName = "test-files"

// GetBlackDuckSecurityContextsPath1 ...
func GetBlackDuckSecurityContextsPath1() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, testDirName, "blackduck-security-context-1.json")
}

// GetBlackDuckSecurityContextsPath2 ...
func GetBlackDuckSecurityContextsPath2() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, testDirName, "blackduck-security-context-2.json")
}

// GetAlertSecurityContextsPath1 ...
func GetAlertSecurityContextsPath1() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, testDirName, "alert-security-context-1.json")
}

// GetAlertSecurityContextsPath2 ...
func GetAlertSecurityContextsPath2() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, testDirName, "alert-security-context-2.json")
}
