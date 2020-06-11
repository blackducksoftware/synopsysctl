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
	"testing"
)

func TestParseImageVersion(t *testing.T) {
	version := "1.0.6"
	valid := ValidateImageVersion(version)
	if valid == false {
		t.Errorf("invalid version format: %+v", version)
	}

	version = "2019.1.0"
	valid = ValidateImageVersion(version)
	if valid == false {
		t.Errorf("invalid version format: %+v", version)
	}

	version = "2019.a.b.c"
	valid = ValidateImageVersion(version)
	if valid == true {
		t.Errorf("version %+v should not be valid", version)
	}

	version = "2019.1.0-SNAPSHOT"
	valid = ValidateImageVersion(version)
	if valid == true {
		t.Errorf("version %+v should not be valid", version)
	}
}

func TestValidateImageString(t *testing.T) {
	testcases := []struct {
		description string
		image       string
		valid       bool
	}{
		{
			description: "repo with path and tag",
			image:       "url.com/imagename:latest",
			valid:       true,
		},
		{
			description: "repo with path and tag",
			image:       "url.com/projectname/imagename:5.0.0",
			valid:       true,
		},
		{
			description: "repo with path without tag",
			image:       "url.com/imagename",
			valid:       false,
		},
		{
			description: "repo with path and port and tag",
			image:       "url.com:80/imagename:latest",
			valid:       true,
		},
		{
			description: "repo with path and port without tag",
			image:       "url.com:80/imagename",
			valid:       false,
		},
		{
			description: "image name only with tag",
			image:       "imagename:1.2.3",
			valid:       false,
		},
		{
			description: "image name only without tag",
			image:       "imagename",
			valid:       false,
		},
	}

	for _, tc := range testcases {
		valid := ValidateFullImageString(tc.image)

		if valid != tc.valid {
			t.Errorf("expected valid=%t, got %t", tc.valid, valid)
		}
	}
}

func TestParseImageTag(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "base",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "2019.4.2",
		},
		{
			name: "edge",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "2019.4.2",
		},
		{
			name: "non version format",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator:latest",
			},
			want: "latest",
		},
		{
			name: "snapshot format",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator:2020.4.0-SNAPSHOT",
			},
			want: "2020.4.0-SNAPSHOT",
		},
		{
			name: "no version tag fed",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator",
			},
			want: "",
		},
		{
			name: "no version tag, but still two or more splits; also testing weird tag",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseImageTag(tt.args.image)
			if got != tt.want {
				t.Errorf("ParseImageTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseImageName(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "base",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "synopsys-operator",
		},
		{
			name: "edge",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "synopsys-operator",
		},
		{
			name: "no version tag fed",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator",
			},
			want: "synopsys-operator",
		},
		{
			name: "no version tag, but still two or more splits; also testing weird tag",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator",
			},
			want: "synopsys-operator",
		},
		{
			name: "no repo",
			args: args{
				image: "synopsys-operator:latest",
			},
			want: "synopsys-operator",
		},
		{
			name: "no repo, no tag",
			args: args{
				image: "synopsys-operator",
			},
			want: "synopsys-operator",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseImageName(tt.args.image)
			if got != tt.want {
				t.Errorf("ParseImageName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseImageRepo(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "base",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "docker.io/blackducksoftware",
		},
		{
			name: "edge",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator:2019.4.2",
			},
			want: "artifactory.test.lab:8321/blackducksoftware",
		},
		{
			name: "no version tag fed",
			args: args{
				image: "docker.io/blackducksoftware/synopsys-operator",
			},
			want: "docker.io/blackducksoftware",
		},
		{
			name: "no version tag, but still two or more splits; also testing weird tag",
			args: args{
				image: "artifactory.test.lab:8321/blackducksoftware/synopsys-operator",
			},
			want: "artifactory.test.lab:8321/blackducksoftware",
		},
		{
			name: "no repo",
			args: args{
				image: "synopsys-operator:latest",
			},
			want: "",
		},
		{
			name: "no repo, no tag",
			args: args{
				image: "synopsys-operator",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseImageRepo(tt.args.image)
			if got != tt.want {
				t.Errorf("ParseImageName() = %v, want %v", got, tt.want)
			}
		})
	}
}
