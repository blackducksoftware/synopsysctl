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

package synopsysctl

import (
	"fmt"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/spf13/cobra"
)

func verifyClusterType(cType string) error {
	if strings.EqualFold(strings.ToUpper(cType), globals.ClusterTypeKubernetes) || strings.EqualFold(strings.ToUpper(cType), globals.ClusterTypeOpenshift) {
		return nil
	}
	return fmt.Errorf("invalid cluster type '%s'", cType)
}

func addChartLocationPathFlag(cmd *cobra.Command) {
	var tmp string
	cmd.Flags().StringVarP(&tmp, "app-resources-path", "", "", "Absolute path to an application Tarball for air-gapped customer")
	// cmd.Flags().MarkHidden("app-resources-path")
}

func addNativeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&globals.NativeClusterType, "target", globals.NativeClusterType, "Type of cluster to generate the resources for [KUBERNETES|OPENSHIFT]")
}
