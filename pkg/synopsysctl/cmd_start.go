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

	alertctl "github.com/blackducksoftware/synopsysctl/pkg/alert"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var startAlertCobraHelper alertctl.HelmValuesFromCobraFlags

// startCmd starts a Synopsys resource in the cluster
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a Synopsys resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("must specify a sub-command")
	},
}

// startAlertCmd starts an Alert instance
var startAlertCmd = &cobra.Command{
	Use:           "alert NAME -n NAMESPACE",
	Example:       "synopsysctl start alert <name> -n <namespace>",
	Short:         "Start an Alert instance",
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
		alertName := args[0]
		helmReleaseName := fmt.Sprintf("%s%s", alertName, AlertPostSuffix)

		instance, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance '%s' in namespace '%s'", alertName, namespace)
		}

		// Update the Helm Chart Location
		alertVersion := util.GetValueFromRelease(instance, []string{"alert", "imageTag"})
		err = SetHelmChartLocation(cmd.Flags(), alertChartName, alertVersion.(string), &alertChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Running")

		err = util.UpdateWithHelm3(helmReleaseName, namespace, alertChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
			return fmt.Errorf("failed to create Alert resources: %+v", cleanErrorMsg)
		}

		log.Infof("successfully submitted start Alert '%s' in namespace '%s'", alertName, namespace)

		return nil
	},
}

// startBlackDuckCmd starts a Black Duck instance
var startBlackDuckCmd = &cobra.Command{
	Use:           "blackduck NAME -n NAMESPACE",
	Example:       "synopsysctl start blackduck <name> -n <namespace>",
	Short:         "Start a Black Duck instance",
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

		instance, err := util.GetWithHelm3(args[0], namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance %s in namespace %s", args[0], namespace)
		}

		// Update the Helm Chart Location
		blackDuckVersion := util.GetValueFromRelease(instance, []string{"imageTag"})
		err = SetHelmChartLocation(cmd.Flags(), blackDuckChartName, blackDuckVersion.(string), &blackduckChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Running")

		err = util.UpdateWithHelm3(args[0], namespace, blackduckChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to create Blackduck resources: %+v", err)
		}
		return nil
	},
}

// startOpsSightCmd starts an OpsSight instance
var startOpsSightCmd = &cobra.Command{
	Use:           "opssight NAME -n NAMESPACE",
	Example:       "synopsysctl start opssight <name> -n <namespace>",
	Short:         "Start an OpsSight instance",
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
		instance, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance %s in namespace %s", opssightName, namespace)
		}

		// Update the Helm Chart Location
		opssightImageTag := util.GetValueFromRelease(instance, []string{"imageTag"}).(string)
		opssightVersion := opssightVersionToChartVersion[opssightImageTag]
		err = SetHelmChartLocation(cmd.Flags(), opssightChartName, opssightVersion, &opssightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Running")

		err = util.UpdateWithHelm3(opssightName, namespace, opssightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to create OpsSight resources: %+v", err)
		}
		return nil
	},
}

func init() {
	startAlertCobraHelper = *alertctl.NewHelmValuesFromCobraFlags()

	rootCmd.AddCommand(startCmd)

	startAlertCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(startAlertCmd.Flags(), "namespace")
	addChartLocationPathFlag(startAlertCmd)
	startCmd.AddCommand(startAlertCmd)

	startBlackDuckCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(startBlackDuckCmd.Flags(), "namespace")
	addChartLocationPathFlag(startBlackDuckCmd)
	startCmd.AddCommand(startBlackDuckCmd)

	startOpsSightCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(startOpsSightCmd.PersistentFlags(), "namespace")
	addChartLocationPathFlag(startOpsSightCmd)
	startCmd.AddCommand(startOpsSightCmd)
}
