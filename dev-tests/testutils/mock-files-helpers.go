package testutils

import "fmt"

var mockDirName = "mock-files"

// GetMockServiceAccount ...
func GetMockServiceAccount() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, mockDirName, "mock-sa.json")
}

// GetMockTLSCertificate ...
func GetMockTLSCertificate() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, mockDirName, "mock-tls.crt")
}

// GetMockTLSKey ...
func GetMockTLSKey() string {
	return fmt.Sprintf("%s/%s/%s", TestConfig.AbsolutePathToTestSuite, mockDirName, "mock-tls.key")
}
