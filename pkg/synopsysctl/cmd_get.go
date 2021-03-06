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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Get Command flag for -output functionality
var getOutputFormat string

// Get Command flag for -selector functionality
var getSelector string

// Get Command flag for --all-namespaces functionality
var getAllNamespaces bool

func generateKubectlGetCommand(resourceName string, args []string) []string {
	kubectlCmd := []string{"get", resourceName}
	if len(namespace) > 0 {
		kubectlCmd = append(kubectlCmd, "-n", namespace)
	}
	if len(args) > 0 {
		kubectlCmd = append(kubectlCmd, args...)
	}
	if getOutputFormat != "" {
		kubectlCmd = append(kubectlCmd, "-o")
		kubectlCmd = append(kubectlCmd, getOutputFormat)
	}
	if getSelector != "" {
		kubectlCmd = append(kubectlCmd, "-l")
		kubectlCmd = append(kubectlCmd, getSelector)
	}
	if getAllNamespaces {
		kubectlCmd = append(kubectlCmd, globals.AllNamespacesFlag)
	}
	return kubectlCmd
}

// getCmd lists resources in the cluster
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Display Synopsys resources from your cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("must specify a sub-command")
	},
}

// getAlertCmd display one or many Alert instances
var getAlertCmd = &cobra.Command{
	Use:           "alert NAME -n NAMESPACE",
	Example:       "synopsysctl get alert <name> -n <namespace>",
	Aliases:       []string{"alerts"},
	Short:         "Display an Alert instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("this command takes 1 argument, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		alertName := args[0]
		helmReleaseName := fmt.Sprintf("%s%s", alertName, globals.AlertPostSuffix)
		helmRelease, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
			return fmt.Errorf("failed to get values for Alert: %+v", cleanErrorMsg)
		}
		helmSetValues := helmRelease.Config
		PrintComponent(helmSetValues, "YAML")
		return nil
	},
}

// getBlackDuckCmd display a Black Duck instances
var getBlackDuckCmd = &cobra.Command{
	Use:           "blackduck NAME -n NAMESPACE",
	Example:       "synopsysctl get blackduck <name> -n <namespace>",
	Aliases:       []string{"blackducks"},
	Short:         "Display a Black Duck instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			cmd.Help()
			return fmt.Errorf("this command takes 1 argument, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		helmRelease, err := util.GetWithHelm3(args[0], namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get Blackduck values: %+v", err)
		}
		helmSetValues := helmRelease.Config
		PrintComponent(helmSetValues, "YAML")
		return nil
	},
}

// getBlackDuckRootKeyCmd get Black Duck master key for source code upload in the cluster
var getBlackDuckRootKeyCmd = &cobra.Command{
	Use:           "masterkey NAME DIRECTORY_PATH_TO_STORE_MASTER_KEY -n NAMESPACE",
	Example:       "synopsysctl get blackduck masterkey <name> <directory path to store the master key> -n <namespace>",
	Short:         "Get the master key of the Black Duck instance that is used for source code upload and store it in the host",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			cmd.Help()
			return fmt.Errorf("this command takes 2 arguments, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return getBlackDuckMasterKey(namespace, args[0], args[1])
	},
}

// getBlackDuckMasterKey will retrieve the master key for the given Black Duck and store it in the file path
func getBlackDuckMasterKey(namespace string, name string, filePath string) error {
	// getting the seal key secret to retrieve the seal key
	secret, err := util.GetSecret(kubeClient, namespace, fmt.Sprintf("%s-blackduck-upload-cache", name))
	if err != nil {
		return fmt.Errorf("unable to find Seal key secret (%s-blackduck-upload-cache) in namespace '%s' due to %+v", name, namespace, err)
	}

	sealKey := string(secret.Data["SEAL_KEY"])

	// Filter the upload cache pod to get the master key using the seal key
	uploadCachePod, err := util.FilterPodByNamePrefixInNamespace(kubeClient, namespace, util.GetResourceName(name, util.BlackDuckName, "uploadcache"))
	if err != nil {
		return fmt.Errorf("unable to filter the upload cache pod in namespace '%s' due to %+v", namespace, err)
	}

	// Create the exec into Kubernetes pod request
	req := util.CreateExecContainerRequest(kubeClient, uploadCachePod, "/bin/sh")

	stdout, err := util.ExecContainer(restconfig, req, []string{fmt.Sprintf(`curl -f --header "X-SEAL-KEY: %s" https://localhost:9444/api/internal/master-key --cert /opt/blackduck/hub/blackduck-upload-cache/security/blackduck-upload-cache-server.crt --key /opt/blackduck/hub/blackduck-upload-cache/security/blackduck-upload-cache-server.key --cacert /opt/blackduck/hub/blackduck-upload-cache/security/root.crt`, base64.StdEncoding.EncodeToString([]byte(sealKey)))})
	if err != nil {
		return fmt.Errorf("unable to exec into upload cache pod in namespace '%s' due to %+v", namespace, err)
	}

	fileName := filepath.Join(filePath, fmt.Sprintf("%s-%s.key", namespace, name))
	os.MkdirAll(filePath, os.ModePerm)
	err = ioutil.WriteFile(fileName, []byte(stdout), 0777)
	if err != nil {
		return fmt.Errorf("error writing to file '%s' due to %+v", fileName, err)
	}
	log.Infof("successfully retrieved the master key and stored it in '%s' file for Black Duck '%s' in namespace '%s'", fileName, name, namespace)
	return nil
}

// getOpsSightCmd display an OpsSight instance
var getOpsSightCmd = &cobra.Command{
	Use:           "opssight NAME -n NAMESPACE",
	Example:       "synopsysctl get opssight -n <namespace>",
	Aliases:       []string{"opssights"},
	Short:         "Display an OpsSight instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			cmd.Help()
			return fmt.Errorf("this command takes 1 argument, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get OpsSight values: %+v", err)
		}
		helmSetValues := helmRelease.Config
		PrintComponent(helmSetValues, "YAML")
		return nil
	},
}

// getBDBACmd display the BDBA instance
var getBDBACmd = &cobra.Command{
	Use:           "bdba -n NAMESPACE",
	Example:       "synopsysctl get bdba -n <namespace>",
	Short:         "Display the BDBA instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("this command takes 0 arguments, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		helmRelease, err := util.GetWithHelm3(globals.BDBAName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get BDBA values: %+v", err)
		}
		helmSetValues := helmRelease.Config
		PrintComponent(helmSetValues, "YAML")
		return nil
	},
}

func init() {
	//(PassCmd) getCmd.DisableFlagParsing = true // lets getCmd pass flags to kube/oc
	rootCmd.AddCommand(getCmd)

	// Alert
	getAlertCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(getAlertCmd.Flags(), "namespace")
	getCmd.AddCommand(getAlertCmd)

	// Black Duck
	getBlackDuckCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(getBlackDuckCmd.PersistentFlags(), "namespace")
	getCmd.AddCommand(getBlackDuckCmd)

	getBlackDuckCmd.AddCommand(getBlackDuckRootKeyCmd)

	// OpsSight
	getOpsSightCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(getOpsSightCmd.PersistentFlags(), "namespace")
	getCmd.AddCommand(getOpsSightCmd)

	// BDBA
	getBDBACmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(getBDBACmd.Flags(), "namespace")
	getCmd.AddCommand(getBDBACmd)
}
