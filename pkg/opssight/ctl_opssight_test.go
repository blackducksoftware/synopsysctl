/*
Copyright (C) 2019 Synopsys, Inc.
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

package opssight

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewHelmValuesFromCobraFlags(t *testing.T) {
	assert := assert.New(t)
	opssightCobraHelper := NewHelmValuesFromCobraFlags()
	assert.Equal(&HelmValuesFromCobraFlags{
		args:     map[string]interface{}{},
		flagTree: FlagTree{},
	}, opssightCobraHelper)
}

func TestGetArgs(t *testing.T) {
	assert := assert.New(t)
	opssightCobraHelper := NewHelmValuesFromCobraFlags()
	assert.Equal(map[string]interface{}{}, opssightCobraHelper.GetArgs())
}

func TestGenerateHelmFlagsFromCobraFlags(t *testing.T) {
	assert := assert.New(t)

	opssightCobraHelper := NewHelmValuesFromCobraFlags()
	cmd := &cobra.Command{}
	opssightCobraHelper.AddCobraFlagsToCommand(cmd, true)
	flagset := cmd.Flags()
	// Set flags here...

	opssightCobraHelper.GenerateHelmFlagsFromCobraFlags(flagset)

	expectedArgs := map[string]interface{}{}

	assert.Equal(expectedArgs, opssightCobraHelper.GetArgs())

}

func TestSetCRSpecFieldByFlag(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		flagName    string
		initialCtl  *HelmValuesFromCobraFlags
		changedCtl  *HelmValuesFromCobraFlags
		changedArgs map[string]interface{}
	}{
		// case
		{
			flagName: "version",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Version: "v",
				},
			},
			changedArgs: map[string]interface{}{
				"imageTag": "v",
			},
		},
		// case
		{
			flagName: "deployment-resources-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					DeploymentResourcesFilePath: "../../examples/synopsysctl/deployment-resources-opssight.json",
				},
			},
			changedArgs: map[string]interface{}{
				"prometheus": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"core": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"podProcessor": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"scanner": map[string]interface{}{
					"replicas": int32(1),
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"imageGetter": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"imageProcessor": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"quayProcessor": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
				"artifactoryProcessor": map[string]interface{}{
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "123m",
							"memory": "3072Mi",
						},
					},
				},
			},
		},
		// case
		{
			flagName: "registry",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Registry: "registry",
				},
			},
			changedArgs: map[string]interface{}{
				"registry": "registry",
			},
		},
		// case
		{
			flagName: "pull-secret-name",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PullSecrets: []string{"secret"},
				},
			},
			changedArgs: map[string]interface{}{
				"imagePullSecrets": []string{"secret"},
			},
		},
		// case
		{
			flagName: "log-level",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					LogLevel: "debug",
				},
			},
			changedArgs: map[string]interface{}{
				"logLevel": "debug",
			},
		},
		// case
		{
			flagName: "blackduck-external-hosts-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					BlackduckExternalHostsFilePath: "../../examples/synopsysctl/blackduckExternalHosts.json",
				},
			},
			changedArgs: map[string]interface{}{
				"externalBlackDuck": []map[string]interface{}{
					{
						"concurrentScanLimit": 88,
						"domain":              "domaina",
						"password":            "passworda",
						"port":                99,
						"scheme":              "schemea",
						"user":                "usera",
					},
					{
						"concurrentScanLimit": 89,
						"domain":              "domainb",
						"password":            "passwordb",
						"port":                100,
						"scheme":              "schemeb",
						"user":                "userb",
					},
				},
			},
		},
		// case
		{
			flagName: "blackduck-secured-registries-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					BlackduckSecuredRegistriesFilePath: "../../examples/synopsysctl/blackduckSecuredRegistries.json",
				},
			},
			changedArgs: map[string]interface{}{
				"securedRegistries": []map[string]interface{}{
					{
						"url":      "urla",
						"user":     "usera",
						"password": "passworda",
						"token":    "tokena",
					},
					{
						"url":      "urlb",
						"user":     "userb",
						"password": "passwordb",
						"token":    "tokenb",
					},
				},
			},
		},
		// case
		{
			flagName: "blackduck-TLS-verification",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					BlackduckTLSVerification: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"blackduck": map[string]interface{}{
					"tlsVerification": true,
				},
			},
		},
		// case
		{
			flagName: "enable-metrics",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EnableMetrics: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"prometheus": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		// case
		{
			flagName: "expose-metrics",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PrometheusExpose: "OPENSHIFT",
				},
			},
			changedArgs: map[string]interface{}{
				"prometheus": map[string]interface{}{
					"expose": "OpenShift",
				},
			},
		},
		// case
		{
			flagName: "opssight-core-expose",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorExpose: "OPENSHIFT",
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"expose": "OpenShift",
				},
			},
		},
		// case
		{
			flagName: "opssight-core-check-scan-hours",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorCheckForStalledScansPauseHours: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"checkForStalledScansPauseHours": 5,
				},
			},
		},
		// case
		{
			flagName: "opssight-core-scan-client-timeout-hours",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorStalledScanClientTimeoutHours: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"stalledScanClientTimeoutHours": 5,
				},
			},
		},
		// case
		{
			flagName: "opssight-core-metrics-pause-seconds",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorModelMetricsPauseSeconds: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"modelMetricsPauseSeconds": 5,
				},
			},
		},
		// case
		{
			flagName: "opssight-core-unknown-image-pause-milliseconds",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorUnknownImagePauseMilliseconds: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"unknownImagePauseMilliseconds": 5,
				},
			},
		},
		// case
		{
			flagName: "opssight-core-client-timeout-milliseconds",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceptorClientTimeoutMilliseconds: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"core": map[string]interface{}{
					"clientTimeoutMilliseconds": 5,
				},
			},
		},
		// // TODO case
		// {
		// 	flagName: "processor-TLS-certificate-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{
		// 			PerceiverTLSCertificatePath: "../../examples/synopsysctl/certificate.txt",
		// 		},
		// 	},
		// 	changedArgs: map[string]interface{}{
		// 		"processor": map[string]interface{}{
		// 			"certificate": "CERTIFICATE",
		// 		}
		// 	},
		// },
		// // TODO case
		// {
		// 	flagName: "processor-TLS-key-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{
		// 			PerceiverTLSCertificatePath: "../../examples/synopsysctl/certificateKey.txt",
		// 		},
		// 	},
		// 	changedArgs: map[string]interface{}{
		// 		"processor": map[string]interface{}{
		// 			"certificateKey": "CERTIFICATE_KEY=CERTIFICATE_KEY_DATA",
		// 		}
		// 	},
		// },
		// case
		{
			flagName: "processor-annotation-interval-seconds",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverAnnotationIntervalSeconds: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"processor": map[string]interface{}{
					"annotationIntervalSeconds": 5,
				},
			},
		},
		// case
		{
			flagName: "processor-dump-interval-minutes",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverDumpIntervalMinutes: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"processor": map[string]interface{}{
					"dumpIntervalMinutes": 5,
				},
			},
		},
		// case
		{
			flagName: "enable-pod-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverEnablePodPerceiver: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"podProcessor": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		// case
		{
			flagName: "pod-processor-namespace-filter",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverPodPerceiverNamespaceFilter: "filter",
				},
			},
			changedArgs: map[string]interface{}{
				"podProcessor": map[string]interface{}{
					"nameSpaceFilter": "filter",
				},
			},
		},
		// case
		{
			flagName: "scanner-client-timeout-seconds",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ScannerPodScannerClientTimeoutSeconds: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"scanner": map[string]interface{}{
					"blackDuckClientTimeoutSeconds": 5,
				},
			},
		},
		// case
		{
			flagName: "scannerpod-replica-count",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ScannerPodReplicaCount: 5,
				},
			},
			changedArgs: map[string]interface{}{
				"scanner": map[string]interface{}{
					"replicas": 5,
				},
			},
		},
		// case
		{
			flagName: "scannerpod-image-directory",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ScannerPodImageDirectory: "imageDirectory",
				},
			},
			changedArgs: map[string]interface{}{
				"scanner": map[string]interface{}{
					"imageDirectory": "imageDirectory",
				},
			},
		},
		// case
		{
			flagName: "image-getter-image-puller-type",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ScannerPodImageFacadeImagePullerType: "puller-type",
				},
			},
			changedArgs: map[string]interface{}{
				"imageGetter": map[string]interface{}{
					"imagePullerType": "puller-type",
				},
			},
		},
		// case
		{
			flagName: "enable-image-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverEnableImagePerceiver: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"imageProcessor": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		// case
		{
			flagName: "enable-quay-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverEnableQuayPerceiver: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"quayProcessor": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		// case
		{
			flagName: "expose-quay-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverQuayExpose: "OPENSHIFT",
				},
			},
			changedArgs: map[string]interface{}{
				"quayProcessor": map[string]interface{}{
					"expose": "OpenShift",
				},
			},
		},
		// case
		{
			flagName: "enable-artifactory-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverEnableArtifactoryPerceiver: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"artifactoryProcessor": map[string]interface{}{
					"enabled": true,
				},
			},
		},
		// case
		{
			flagName: "enable-artifactory-processor-dumper",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverEnableArtifactoryPerceiverDumper: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"artifactoryProcessor": map[string]interface{}{
					"dumper": true,
				},
			},
		},
		// case
		{
			flagName: "expose-artifactory-processor",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PerceiverArtifactoryExpose: "OPENSHIFT",
				},
			},
			changedArgs: map[string]interface{}{
				"artifactoryProcessor": map[string]interface{}{
					"expose": "OpenShift",
				},
			},
		},
	}

	// get the flagset
	cmd := &cobra.Command{}
	opssightCobraHelper := NewHelmValuesFromCobraFlags()
	opssightCobraHelper.AddCobraFlagsToCommand(cmd, true)
	flagset := cmd.Flags()

	for _, test := range tests {
		// check the Flag exists
		foundFlag := flagset.Lookup(test.flagName)
		if foundFlag == nil {
			t.Errorf("flag %s is not in the spec", test.flagName)
		}
		// test setting the flag
		f := &pflag.Flag{Changed: true, Name: test.flagName}
		opssightCobraHelper = test.changedCtl
		opssightCobraHelper.args = map[string]interface{}{}
		fs := &pflag.FlagSet{}
		fs.AddFlag(f)
		opssightCobraHelper.GenerateHelmFlagsFromCobraFlags(fs)
		assert.Equal(test.changedArgs, opssightCobraHelper.GetArgs())
	}

	// case: nothing set if flag doesn't exist
	opssightCobraHelper = NewHelmValuesFromCobraFlags()
	f := &pflag.Flag{Changed: true, Name: "bad-flag"}
	fs := &pflag.FlagSet{}
	fs.AddFlag(f)
	opssightCobraHelper.GenerateHelmFlagsFromCobraFlags(fs)
	assert.Equal(map[string]interface{}{}, opssightCobraHelper.GetArgs())

}
