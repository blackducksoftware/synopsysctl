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
	"testing"
)

func TestCompareVersions(t *testing.T) {
	testcases := []struct {
		description string
		v1          string
		v2          string
		expected    int
	}{
		{
			description: "",
			v1:          "2020.4.1",
			v2:          "2020.4.1",
			expected:    0,
		},
		{
			description: "",
			v1:          "2020.4.0",
			v2:          "2020.4.1",
			expected:    -1,
		},
		{
			description: "",
			v1:          "2020.4.1",
			v2:          "2020.4.0",
			expected:    1,
		},
		{
			description: "",
			v1:          "2020.3.1",
			v2:          "2020.4.0",
			expected:    -1,
		},
		{
			description: "",
			v1:          "2020.3.1",
			v2:          "2020.2.1",
			expected:    1,
		},
		{
			description: "",
			v1:          "2019.12.1",
			v2:          "2020.2.1",
			expected:    -1,
		},
		{
			description: "",
			v1:          "2020.12.1",
			v2:          "2019.2.1",
			expected:    1,
		},
		{
			description: "",
			v1:          "2020.03",
			v2:          "2019.04",
			expected:    1,
		},
		{
			description: "",
			v1:          "2020.3",
			v2:          "2019.04",
			expected:    1,
		},
		{
			description: "",
			v1:          "2020.03",
			v2:          "2020.03",
			expected:    0,
		},
		{
			description: "",
			v1:          "2020.04.1",
			v2:          "2020.04",
			expected:    1,
		},
		{
			description: "",
			v1:          "2020.04",
			v2:          "2020.03.1",
			expected:    1,
		},
	}

	for _, tc := range testcases {
		out := CompareVersions(tc.v1, tc.v2)

		if out != tc.expected {
			t.Errorf("compare %s to %s - expected %+v, got %+v", tc.v1, tc.v2, tc.expected, out)
		}
	}
}
