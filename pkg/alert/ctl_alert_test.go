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

package alert

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewHelmValuesFromCobraFlags(t *testing.T) {
	assert := assert.New(t)
	cobraHelper := NewHelmValuesFromCobraFlags()
	assert.Equal(&HelmValuesFromCobraFlags{
		args:     map[string]interface{}{},
		flagTree: FlagTree{},
	}, cobraHelper)
}

func TestGetArgs(t *testing.T) {
	assert := assert.New(t)
	cobraHelper := NewHelmValuesFromCobraFlags()
	assert.Equal(map[string]interface{}{}, cobraHelper.GetArgs())
}

func TestGenerateHelmFlagsFromCobraFlags(t *testing.T) {
	assert := assert.New(t)

	cobraHelper := NewHelmValuesFromCobraFlags()
	cmd := &cobra.Command{}
	cobraHelper.AddCobraFlagsToCommand(cmd, true)
	flagset := cmd.Flags()
	// Set flags here...

	cobraHelper.GenerateHelmFlagsFromCobraFlags(flagset)

	expectedArgs := map[string]interface{}{}

	assert.Equal(expectedArgs, cobraHelper.GetArgs())

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
					Version: "latest",
				},
			},
			changedArgs: map[string]interface{}{
				"alert": map[string]interface{}{
					"imageTag": "latest",
				},
			},
		},
		// case
		{
			flagName: "standalone",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					StandAlone: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"enableStandalone": true,
			},
		},
		// case
		{
			flagName: "deployment-resources-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					DeploymentResourcesFilePath: "../../examples/synopsysctl/deployment-resources-test.json",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"heapMaxMemory": "3096m",
					"replicas":      int32(1),
					"resources": map[string]interface{}{
						"requests": map[string]interface{}{
							"cpu":    "1000m",
							"memory": "3072Mi",
						},
					},
				},
			},
		},
		// case
		{
			flagName: "expose-ui",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExposeService: "NODEPORT",
				},
			},
			changedArgs: map[string]interface{}{
				"exposeui":           true,
				"exposedServiceType": "NodePort",
			},
		},
		// case
		{
			flagName: "encryption-password",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EncryptionPassword: "abcdabcdabcdabcd",
				},
			},
			changedArgs: map[string]interface{}{
				"setEncryptionSecretData": true,
				"alertEncryptionPassword": "abcdabcdabcdabcd",
			},
		},
		// case
		{
			flagName: "encryption-global-salt",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EncryptionGlobalSalt: "abcdabcdabcdabcd",
				},
			},
			changedArgs: map[string]interface{}{
				"setEncryptionSecretData":   true,
				"alertEncryptionGlobalSalt": "abcdabcdabcdabcd",
			},
		},
		// case
		{
			flagName: "persistent-storage",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PersistentStorage: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"enablePersistentStorage": true,
			},
		},
		// TODO case
		{
			flagName: "pvc-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PVCFilePath: "../../examples/synopsysctl/pvc-alert.json",
				},
			},
			changedArgs: map[string]interface{}{
				"alert": map[string]interface{}{
					"persistentVolumeClaimName": "",
					"claimSize":                 "custom",
					"storageClass":              "custom",
					"volumeName":                "custom",
				},
			},
		},
		// case
		{
			flagName: "pvc-storage-class",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PVCStorageClass: "storageclass",
				},
			},
			changedArgs: map[string]interface{}{
				"storageClass": "storageclass",
			},
		},
		// case
		{
			flagName: "environs",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Environs: []string{"ENV1:VAL1", "ENV2:VAL2"},
				},
			},
			changedArgs: map[string]interface{}{
				"environs": map[string]interface{}{
					"ENV1": "VAL1",
					"ENV2": "VAL2",
				},
			},
		},
		// case
		{
			flagName: "registry",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Registry: "registryName",
				},
			},
			changedArgs: map[string]interface{}{
				"registry": "registryName",
			},
		},
		// case
		{
			flagName: "pull-secret-name",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PullSecrets: []string{"secret1", "secret2"},
				},
			},
			changedArgs: map[string]interface{}{
				"imagePullSecrets": []string{"secret1", "secret2"},
			},
		},
		// case
		{
			flagName: "certificate-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					CertificateFilePath: "filepath",
				},
			},
			changedArgs: map[string]interface{}{},
		},
		// case
		{
			flagName: "certificate-key-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					CertificateKeyFilePath: "filepath",
				},
			},
			changedArgs: map[string]interface{}{},
		},
		// case
		{
			flagName: "java-keystore-file-path",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					JavaKeyStoreFilePath: "filepath",
				},
			},
			changedArgs: map[string]interface{}{},
		},
		// case
		// {
		// 	flagName:    "security-context-file-path",
		// 	changedCtl:  &HelmValuesFromCobraFlags{},
		// 	changedArgs: map[string]interface{}{},
		// },
		// case
		{
			flagName: "port",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Port: int32(1234),
				},
			},
			changedArgs: map[string]interface{}{
				"alert": map[string]interface{}{
					"port": int32(1234),
				},
			},
		},
	}

	// get the flagset
	cmd := &cobra.Command{}
	cobraHelper := NewHelmValuesFromCobraFlags()
	cobraHelper.AddCobraFlagsToCommand(cmd, true)
	flagset := cmd.Flags()

	for _, test := range tests {
		fmt.Printf("Testing flag '%s':\n", test.flagName)
		// check the Flag exists
		foundFlag := flagset.Lookup(test.flagName)
		if foundFlag == nil {
			t.Errorf("flag '%s' is not in the spec", test.flagName)
		}
		// test setting the flag
		f := &pflag.Flag{Changed: true, Name: test.flagName}
		cobraHelper = test.changedCtl
		cobraHelper.args = map[string]interface{}{}
		cobraHelper.AddHelmValueByCobraFlag(f)
		if isEqual := assert.Equal(test.changedArgs, cobraHelper.GetArgs()); !isEqual {
			t.Errorf("failed case for flag '%s'", test.flagName)
		}
	}

	// case: nothing set if flag doesn't exist
	cobraHelper = NewHelmValuesFromCobraFlags()
	f := &pflag.Flag{Changed: true, Name: "bad-flag"}
	cobraHelper.AddHelmValueByCobraFlag(f)
	assert.Equal(map[string]interface{}{}, cobraHelper.GetArgs())

}
