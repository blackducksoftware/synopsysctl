/*
 * Copyright (C) 2020 Synopsys, Inc.
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 *  under the License.
 */

package util

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetHelmValueInMap(t *testing.T) {
	type test struct {
		testDesc   string
		startMap   map[string]interface{}
		keyString  []string
		finalValue interface{}
		finalMap   map[string]interface{}
	}
	tests := []test{
		{
			testDesc:   "empty key string and empty startMap",
			startMap:   map[string]interface{}{},
			keyString:  []string{},
			finalValue: "finalValue",
			finalMap:   map[string]interface{}{},
		},
		{
			testDesc: "empty key string and non-empty startMap",
			startMap: map[string]interface{}{
				"first": "otherValue",
			},
			keyString:  []string{},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first": "otherValue",
			},
		},
		{
			testDesc:   "place value into empty map with one key",
			startMap:   map[string]interface{}{},
			keyString:  []string{"first"},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first": "finalValue",
			},
		},
		{
			testDesc: "override value in map",
			startMap: map[string]interface{}{
				"first": "oldValue",
			},
			keyString:  []string{"first"},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first": "finalValue",
			},
		},
		{
			testDesc:   "place value into empty map with multiple keys",
			startMap:   map[string]interface{}{},
			keyString:  []string{"first", "second"},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": "finalValue",
				},
			},
		},
		{
			testDesc: "place value into non-empty map with one key",
			startMap: map[string]interface{}{
				"first": "otherValue",
			},
			keyString:  []string{"second"},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first":  "otherValue",
				"second": "finalValue",
			},
		},
		{
			testDesc: "place value into non-empty map with nested keys",
			startMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": "otherValue",
				},
			},
			keyString:  []string{"first", "third"},
			finalValue: "finalValue",
			finalMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": "otherValue",
					"third":  "finalValue",
				},
			},
		},
		{
			testDesc:   "value is non-string",
			startMap:   map[string]interface{}{},
			keyString:  []string{"first", "second"},
			finalValue: 1234,
			finalMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": 1234,
				},
			},
		},
	}
	for _, tt := range tests {
		SetHelmValueInMap(tt.startMap, tt.keyString, tt.finalValue)
		assert := assert.New(t)
		assert.Equal(tt.startMap, tt.finalMap, fmt.Sprintf("failed case: %s\nGot: %+v\nWanted: %+v", tt.testDesc, tt.startMap, tt.finalMap))
	}
}

func TestGetHelmValueFromMap(t *testing.T) {
	type test struct {
		testDesc      string
		valueMap      map[string]interface{}
		keyString     []string
		expectedValue interface{}
		finalMap      map[string]interface{}
	}
	tests := []test{
		{
			testDesc:      "empty key string and empty valueMap",
			valueMap:      map[string]interface{}{},
			keyString:     []string{},
			expectedValue: nil,
		},
		{
			testDesc: "empty key string and non-empty valueMap",
			valueMap: map[string]interface{}{
				"first": "otherValue",
			},
			keyString:     []string{},
			expectedValue: nil,
		},
		{
			testDesc:      "invalid path with empty map returns nil",
			valueMap:      map[string]interface{}{},
			keyString:     []string{"first"},
			expectedValue: nil,
		},
		{
			testDesc: "invalid path with non-empty map returns nil",
			valueMap: map[string]interface{}{
				"first": "VALUE",
			},
			keyString:     []string{"second"},
			expectedValue: nil,
		},
		{
			testDesc: "invalid path with non-empty map returns nil",
			valueMap: map[string]interface{}{
				"first": "VALUE",
			},
			keyString:     []string{"first", "second"},
			expectedValue: nil,
		},
		{
			testDesc: "find value in map",
			valueMap: map[string]interface{}{
				"first": "VALUE",
			},
			keyString:     []string{"first"},
			expectedValue: "VALUE",
		},
		{
			testDesc: "find value in map with multiple keys",
			valueMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": "VALUE",
				},
			},
			keyString:     []string{"first", "second"},
			expectedValue: "VALUE",
		},
		{
			testDesc: "find an int value",
			valueMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": 1234,
				},
			},
			keyString:     []string{"first", "second"},
			expectedValue: 1234,
		},
		{
			testDesc: "find an bool value",
			valueMap: map[string]interface{}{
				"first": map[string]interface{}{
					"second": false,
				},
			},
			keyString:     []string{"first", "second"},
			expectedValue: false,
		},
	}
	for _, tt := range tests {
		receivedValue := GetHelmValueFromMap(tt.valueMap, tt.keyString)
		assert := assert.New(t)
		assert.Equal(tt.expectedValue, receivedValue, fmt.Sprintf("failed case: %s\nGot: %+v\nWanted: %+v", tt.testDesc, receivedValue, tt.expectedValue))
	}
}

func TestParsePackageName(t *testing.T) {
	testcases := []struct {
		description string
		packageName string
		expected    []string
	}{
		{
			description: "",
			packageName: "synopsys-alert-5.3.1",
			expected:    []string{"synopsys-alert", "5.3.1", ""},
		},
		{
			description: "",
			packageName: "synopsys-alert-5.3.1-1",
			expected:    []string{"synopsys-alert", "5.3.1", "1"},
		},
		{
			description: "",
			packageName: "synopsys-alert-5.3.1-12",
			expected:    []string{"synopsys-alert", "5.3.1", "12"},
		},
		{
			description: "",
			packageName: "blackduck-2020.4.2",
			expected:    []string{"blackduck", "2020.4.2", ""},
		},
		{
			description: "",
			packageName: "blackduck-2020.4.2-1",
			expected:    []string{"blackduck", "2020.4.2", "1"},
		},
		{
			description: "",
			packageName: "blackduck-2020.4.2-12",
			expected:    []string{"blackduck", "2020.4.2", "12"},
		},
		{
			description: "",
			packageName: "bdba-2020.04",
			expected:    []string{"bdba", "2020.04", ""},
		},
		{
			description: "",
			packageName: "bdba-2020.04-1",
			expected:    []string{"bdba", "2020.04", "1"},
		},
		{
			description: "",
			packageName: "https://sig-repo.synopsys.com/sig-cloudnative/synopsys-alert-5.3.1.tgz",
			expected:    []string{"synopsys-alert", "5.3.1", ""},
		},
	}

	for _, tc := range testcases {
		out := ParsePackageName(tc.packageName)

		if !reflect.DeepEqual(out, tc.expected) {
			t.Errorf("expected %+v, got %+v", tc.expected, out)
		}
	}
}

func TestGetLatestChartForAppVersionHelper(t *testing.T) {
	testcases := []struct {
		description string
		appName     string
		version     string
		chartURLs   []string
		expected    string
	}{
		{
			description: "",
			appName:     "blackduck",
			version:     "2020.4.1",
			chartURLs: []string{
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
			},
			expected: "https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
		},
		{
			description: "",
			appName:     "blackduck",
			version:     "2020.4.1",
			chartURLs: []string{
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.2.tgz",
			},
			expected: "https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
		},
	}

	for _, tc := range testcases {
		out, err := GetLatestChartURLForAppVersionHelper(tc.chartURLs, tc.appName, tc.version)
		if err != nil {
			t.Errorf("%+v", err)
		}

		if !reflect.DeepEqual(out, tc.expected) {
			t.Errorf("expected %+v, got %+v", tc.expected, out)
		}
	}
}

func TestGetLatestChartURLForAppHelper(t *testing.T) {
	testcases := []struct {
		description string
		appName     string
		chartURLs   []string
		expected    string
	}{
		{
			description: "",
			appName:     "blackduck",
			chartURLs: []string{
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
			},
			expected: "https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
		},
		{
			description: "",
			appName:     "blackduck",
			chartURLs: []string{
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.1-1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.2.tgz",
			},
			expected: "https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.2.tgz",
		},
		{
			description: "",
			appName:     "synopsys-alert",
			chartURLs: []string{
				"https://sig-repo.synopsys.com/sig-cloudnative/synopsys-alert-5.3.1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/synopsys-alert-5.3.2-1.tgz",
				"https://sig-repo.synopsys.com/sig-cloudnative/blackduck-2020.4.2.tgz",
			},
			expected: "https://sig-repo.synopsys.com/sig-cloudnative/synopsys-alert-5.3.2-1.tgz",
		},
	}

	for _, tc := range testcases {
		out, err := GetLatestChartURLForAppHelper(tc.chartURLs, tc.appName)
		if err != nil {
			t.Errorf("%+v", err)
		}

		if !reflect.DeepEqual(out, tc.expected) {
			t.Errorf("expected %+v, got %+v", tc.expected, out)
		}
	}
}
