/*
Copyright (C) 2018 Synopsys, Inc.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
*/

package util

import (
	"regexp"
)

// ValidateFullImageString takes a docker image string and
// verifies a repo, name, and tag were all provided
// image := "docker.io/blackducksoftware/synopsys-operator:latest"
// subMatch = [blackducksoftware/synopsys-operator:latest blackducksoftware synopsys-operator latest]
func ValidateFullImageString(image string) bool {
	fullImageRegexp := regexp.MustCompile(`([0-9a-zA-Z-_:\\.]*)/([0-9a-zA-Z-_:\\.]*):([a-zA-Z0-9-\\._]+)$`)
	imageSubstringSubmatch := fullImageRegexp.FindStringSubmatch(image)
	if len(imageSubstringSubmatch) == 4 {
		return true
	}
	return false
}

// ValidateImageVersion takes a docker image version string and
// verifies that it follows the format x.x.x
// version := "2019.4.2"
// subMatch = [2019.4.2 2019 4 2]
func ValidateImageVersion(version string) bool {
	imageVersionRegexp := regexp.MustCompile(`([0-9]+).([0-9]+).([0-9]+)$`)
	versionSubstringSubmatch := imageVersionRegexp.FindStringSubmatch(version)
	if len(versionSubstringSubmatch) == 4 {
		return true
	}
	return false
}

// ParseImageTag takes a docker image string and returns the tag
// image := "docker.io/blackducksoftware/synopsys-operator:latest"
// subMatch = [blackducksoftware/synopsys-operator:latest latest]
func ParseImageTag(image string) string {
	imageTagRegexp := regexp.MustCompile(`[0-9a-zA-Z-_:\/.]*:([a-zA-Z0-9-\\._]+)$`)
	tagSubstringSubmatch := imageTagRegexp.FindStringSubmatch(image)
	if len(tagSubstringSubmatch) == 2 {
		return tagSubstringSubmatch[1]
	}
	return ""
}

// ParseImageName takes a docker image string and returns the name
// image := "docker.io/blackducksoftware/synopsys-operator:latest"
// subMatch = [blackducksoftware/synopsys-operator:latest docker.io/blackducksoftware/ synopsys-operator :latest]
func ParseImageName(image string) string {
	imageNameRegexp := regexp.MustCompile(`([0-9a-zA-Z-_:\/.]+\/)*([0-9a-zA-Z-_\.]+):?[a-zA-Z0-9-\\._]*$`)
	nameSubstringSubmatch := imageNameRegexp.FindStringSubmatch(image)
	if len(nameSubstringSubmatch) < 2 {
		return ""
	}
	return nameSubstringSubmatch[len(nameSubstringSubmatch)-1]
}

// ParseImageRepo takes a docker image string and returns the repo
// image := "docker.io/blackducksoftware/synopsys-operator:latest"
// subMatch = [blackducksoftware/synopsys-operator:latest docker.io/blackducksoftware/ synopsys-operator :latest]
func ParseImageRepo(image string) string {
	repoRegexp := regexp.MustCompile(`([0-9a-zA-Z-_:\/.]+)\/[0-9a-zA-Z-_\.]+:?[a-zA-Z0-9-\\._]*$`)
	repoSubstringSubmatch := repoRegexp.FindStringSubmatch(image)
	if len(repoSubstringSubmatch) != 2 {
		return ""
	}
	return repoSubstringSubmatch[1]
}
