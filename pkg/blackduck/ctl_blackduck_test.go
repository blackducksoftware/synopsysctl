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

package blackduck

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
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
				"imageTag": "latest",
			},
		},
		// case
		{
			flagName: "size",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Size: "small",
				},
			},
			changedArgs: map[string]interface{}{
				"size": "small",
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
			flagName: "node-port",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExposedNodePort: "1234",
				},
			},
			changedArgs: map[string]interface{}{
				"exposedNodePort": "1234",
			},
		},
		// case
		{
			flagName: "environs",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					Environs: []string{"A:B", "C:D"},
				},
			},
			changedArgs: map[string]interface{}{
				"environs": map[string]interface{}{
					"A": "B",
					"C": "D",
				},
			},
		},
		// case
		{
			flagName: "enable-binary-analysis",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EnableBinaryAnalysis: true,
				},
			},
			changedArgs: map[string]interface{}{
				"enableBinaryScanner": true,
			},
		},
		// case
		{
			flagName: "enable-source-code-upload",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EnableSourceCodeUpload: true,
				},
			},
			changedArgs: map[string]interface{}{
				"enableSourceCodeUpload": true,
			},
		},
		// case
		{
			flagName: "external-postgres-host",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresHost: "host",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"host": "host",
				},
			},
		},
		// case
		{
			flagName: "external-postgres-port",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresPort: 1234,
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"port": 1234,
				},
			},
		},
		// case
		{
			flagName: "external-postgres-admin",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresAdmin: "admin",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"adminUserName": "admin",
				},
			},
		},
		// case
		{
			flagName: "external-postgres-user",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresUser: "user",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"userUserName": "user",
				},
			},
		},
		// case
		{
			flagName: "external-postgres-ssl",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresSsl: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"ssl": true,
				},
			},
		},
		// case
		{
			flagName: "external-postgres-admin-password",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresAdminPassword: "password",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"adminPassword": "password",
				},
			},
		},
		// case
		{
			flagName: "external-postgres-user-password",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					ExternalPostgresUserPassword: "password",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"userPassword": "password",
				},
			},
		},
		// case
		{
			flagName: "postgres-init-post-command",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PostgresInitPostCommand: "curl -X POST http://localhost:15020/quitquitquit",
				},
			},
			changedArgs: map[string]interface{}{
				"init": map[string]interface{}{
					"postCommand": "curl -X POST http://localhost:15020/quitquitquit",
				},
			},
		},
		// case
		{
			flagName: "pvc-storage-class",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PvcStorageClass: "storageclass",
				},
			},
			changedArgs: map[string]interface{}{
				"storageClass": "storageclass",
			},
		},
		// case
		{
			flagName: "liveness-probes",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					LivenessProbes: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"enableLivenessProbe": true,
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
		// case
		{
			flagName: "enable-init-container",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					EnableInitContainer: "true",
				},
			},
			changedArgs: map[string]interface{}{
				"enableInitContainer": true,
			},
		},
		// // case TODO
		// {
		// 	flagName: "pvc-file-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// // case TODO
		// {
		// 	flagName: "deployment-resources-file-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// // case TODO
		// {
		// 	flagName: "node-affinity-file-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// // case TODO
		// {
		// 	flagName: "security-context-file-path",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// case
		{
			flagName: "postgres-claim-size",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					PostgresClaimSize: "claim",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"claimSize": "claim",
				},
			},
		},
		// case
		{
			flagName: "admin-password",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					AdminPassword: "password",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"adminPassword": "password",
					"isExternal":    false,
				},
			},
		},
		// case
		{
			flagName: "user-password",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					UserPassword: "password",
				},
			},
			changedArgs: map[string]interface{}{
				"postgres": map[string]interface{}{
					"userPassword": "password",
					"isExternal":   false,
				},
			},
		},
		// // case TODO
		// {
		// 	flagName: "registry",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// // case TODO
		// {
		// 	flagName: "image-registries",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// // case TODO
		// {
		// 	flagName: "pull-secret-name",
		// 	changedCtl: &HelmValuesFromCobraFlags{
		// 		flagTree: FlagTree{},
		// 	},
		// 	changedArgs: map[string]interface{}{},
		// },
		// case
		{
			flagName: "seal-key",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					SealKey: "abcdefghijklmnopqrstuvwxyz123456",
				},
			},
			changedArgs: map[string]interface{}{
				"sealKey": "abcdefghijklmnopqrstuvwxyz123456",
			},
		},
		// case
		{
			flagName: "redis-tls-enabled",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					RedisTLSEnabled: false,
				},
			},
			changedArgs: map[string]interface{}{
				"redis": map[string]interface{}{
					"tlsEnabled": false,
				},
			},
		},
		// case
		{
			flagName: "redis-max-total",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					RedisMaxTotalConnection: 128,
				},
			},
			changedArgs: map[string]interface{}{
				"redis": map[string]interface{}{
					"maxTotal": 128,
				},
			},
		},
		// case
		{
			flagName: "redis-max-idle",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					RedisMaxIdleConnection: 128,
				},
			},
			changedArgs: map[string]interface{}{
				"redis": map[string]interface{}{
					"maxIdle": 128,
				},
			},
		},
		// case
		{
			flagName: "is-azure",
			changedCtl: &HelmValuesFromCobraFlags{
				flagTree: FlagTree{
					IsAzure: false,
				},
			},
			changedArgs: map[string]interface{}{
				"isAzure": false,
			},
		},
	}

	// get the flagset
	cmd := &cobra.Command{}
	cobraHelper := NewHelmValuesFromCobraFlags()
	cobraHelper.AddCobraFlagsToCommand(cmd, true)
	appFlagset := cmd.Flags()

	for _, test := range tests {
		fmt.Printf("Testing flag '%s':\n", test.flagName)
		// check the Flag exists
		foundFlag := appFlagset.Lookup(test.flagName)
		if foundFlag == nil {
			t.Errorf("flag '%s' is not in the spec", test.flagName)
		}
		// test setting the flags
		newCmd := &cobra.Command{}
		cobraHelper.AddCobraFlagsToCommand(newCmd, true)
		flagset := newCmd.Flags()
		flagset.Lookup(test.flagName).Changed = true
		cobraHelper = test.changedCtl
		cobraHelper.args = map[string]interface{}{}
		cobraHelper.GenerateHelmFlagsFromCobraFlags(flagset)

		if isEqual := assert.Equal(test.changedArgs, cobraHelper.GetArgs()); !isEqual {
			t.Errorf("failed case for flag '%s'", test.flagName)
		}
	}
}
