/*
Copyright (C) 2020 Synopsys, Inc.

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
	"fmt"
	"strconv"
	"strings"
	"time"
)

// IsNotDefaultVersionGreaterThanOrEqualTo returns whether the given version is greater than or equal to the given inputs
func IsNotDefaultVersionGreaterThanOrEqualTo(version string, majorRelease int, minorRelease int, dotRelease int) (bool, error) {
	versionArr := strings.Split(version, ".")
	if len(versionArr) >= 3 {
		majorReleaseVersion, err := strconv.Atoi(versionArr[0])
		if err != nil {
			return false, err
		}
		minorReleaseVersion, err := strconv.Atoi(versionArr[1])
		if err != nil {
			return false, err
		}
		dotReleaseVersion, err := strconv.Atoi(versionArr[2])
		if err != nil {
			return false, err
		}
		if (majorReleaseVersion > majorRelease) ||
			(majorReleaseVersion == majorRelease && minorReleaseVersion > minorRelease) ||
			(majorReleaseVersion == majorRelease && minorReleaseVersion == minorRelease && dotReleaseVersion >= dotRelease) {
			return true, nil
		}
	}
	return false, nil
}

// IsBlackDuckVersionSupportMultipleInstance returns whether it supports multiple instance in a single namespace
func IsBlackDuckVersionSupportMultipleInstance(version string) (bool, error) {
	return isYearAndMonthGreaterThanOrEqualTo(version, 2019, time.August)
}

// isYearAndMonthGreaterThanOrEqualTo returns whether the given version is greater than or equal to the given year and month
func isYearAndMonthGreaterThanOrEqualTo(version string, year int, month time.Month) (bool, error) {
	versionArr := strings.Split(version, ".")
	if len(versionArr) >= 3 {
		t, err := time.Parse("2006.1", fmt.Sprintf("%s.%s", versionArr[0], versionArr[1]))
		if err != nil {
			return false, err
		}
		if t.Year() >= year && t.Month() >= month {
			return true, nil
		}
	}
	return false, nil
}

// IsVersionEqualTo returns whether the given version is equal to the given year, month and dot release
func IsVersionEqualTo(version string, year int, month time.Month, dotRelease int) (bool, error) {
	versionArr := strings.Split(version, ".")
	if len(versionArr) >= 3 {
		t, err := time.Parse("2006.1", fmt.Sprintf("%s.%s", versionArr[0], versionArr[1]))
		if err != nil {
			return false, err
		}

		minorDotVersion, err := strconv.Atoi(versionArr[2])
		if err != nil {
			return false, err
		}

		if t.Year() == year && t.Month() == month && minorDotVersion == dotRelease {
			return true, nil
		}
	}
	return false, nil
}

// CompareVersions returns an int representing version comparison
// if version1 < version2 -> -1
// if version1 == version2 -> 0
// if version1 > version2 -> 1
func CompareVersions(version1 string, version2 string) int {
	v1Arr := strings.Split(version1, ".")
	v2Arr := strings.Split(version2, ".")

	v1 := StringSliceToIntSlice(v1Arr)

	v2 := StringSliceToIntSlice(v2Arr)

	return CompareVersionsHelper(v1, v2)
}

// CompareVersionsHelper ...
func CompareVersionsHelper(v1, v2 []int) int {
	if len(v1) > 0 && len(v2) > 0 {
		if v1[0] > v2[0] {
			return 1
		}
		if v1[0] < v2[0] {
			return -1
		}
		return CompareVersionsHelper(v1[1:], v2[1:])
	}
	if len(v1) == 0 && len(v2) == 0 {
		return 0
	}
	if len(v2) == 0 {
		return 1
	}
	if len(v1) == 0 {
		return -1
	}
	return 0
}

// StringSliceToIntSlice ...
func StringSliceToIntSlice(vs []string) []int {
	vsm := make([]int, len(vs))
	for i, v := range vs {
		out, _ := strconv.Atoi(v) // if err then the value is 0
		vsm[i] = out
	}
	return vsm
}
