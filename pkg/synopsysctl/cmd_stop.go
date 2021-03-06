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
	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var stopAlertCobraHelper alertctl.HelmValuesFromCobraFlags

// stopCmd stops a Synopsys resource in the cluster
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a Synopsys resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("must specify a sub-command")
	},
}

// stopAlertCmd stops an Alert instance
var stopAlertCmd = &cobra.Command{
	Use:           "alert NAME -n NAMESPACE",
	Example:       "synopsysctl stop alert <name> -n <namespace>",
	Short:         "Stop an Alert instance",
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
		helmReleaseName := fmt.Sprintf("%s%s", alertName, globals.AlertPostSuffix)

		instance, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance '%s' in namespace '%s'", alertName, namespace)
		}

		// Update the Helm Chart Location
		alertVersionFromRelease := util.GetValueFromRelease(instance, []string{"alert", "imageTag"}).(string)
		err = UpdateHelmChartLocation(cmd.Flags(), globals.AlertChartName, alertVersionFromRelease, &globals.AlertChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Stopped")

		err = util.UpdateWithHelm3(helmReleaseName, namespace, globals.AlertChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
			return fmt.Errorf("failed to create Alert resources: %+v", cleanErrorMsg)
		}

		log.Infof("successfully submitted stop Alert '%s' in namespace '%s'", alertName, namespace)

		return nil
	},
}

// stopBlackDuckCmd stops a Black Duck instance
var stopBlackDuckCmd = &cobra.Command{
	Use:           "blackduck NAME -n NAMESPACE",
	Example:       "synopsysctl stop blackduck <name> -n <namespace>",
	Short:         "Stop a Black Duck instance",
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
		blackDuckVersionFromRelease := util.GetValueFromRelease(instance, []string{"imageTag"}).(string)
		err = UpdateHelmChartLocation(cmd.Flags(), globals.BlackDuckChartName, blackDuckVersionFromRelease, &globals.BlackDuckChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Stopped")

		err = util.UpdateWithHelm3(args[0], namespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to create Blackduck resources: %+v", err)
		}
		return nil
	},
}

// stopOpsSightCmd stops an OpsSight instance
var stopOpsSightCmd = &cobra.Command{
	Use:           "opssight NAME -n NAMESPACE",
	Example:       "synopsysctl stop opssight <name> -n <namespace>",
	Short:         "Stop an OpsSight instance",
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
		opsSightVersionFromRelease := util.GetValueFromRelease(instance, []string{"imageTag"}).(string)
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, opsSightVersionFromRelease, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		helmValuesMap := instance.Config
		util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Stopped")

		err = util.UpdateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to create OpsSight resources: %+v", err)
		}
		return nil
	},
}

func init() {
	stopAlertCobraHelper = *alertctl.NewHelmValuesFromCobraFlags()

	rootCmd.AddCommand(stopCmd)

	stopAlertCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(stopAlertCmd.Flags(), "namespace")
	addChartLocationPathFlag(stopAlertCmd)
	stopCmd.AddCommand(stopAlertCmd)

	stopBlackDuckCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(stopBlackDuckCmd.Flags(), "namespace")
	addChartLocationPathFlag(stopBlackDuckCmd)
	stopCmd.AddCommand(stopBlackDuckCmd)

	stopOpsSightCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(stopOpsSightCmd.PersistentFlags(), "namespace")
	addChartLocationPathFlag(stopOpsSightCmd)
	stopCmd.AddCommand(stopOpsSightCmd)
}
