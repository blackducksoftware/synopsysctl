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

	polarisreporting "github.com/blackducksoftware/synopsysctl/pkg/polaris-reporting"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var promptAnswerYes bool

// deleteCmd deletes a resource from the cluster
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove Synopsys resources from your cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("must specify a sub-command")
	},
}

// deleteAlertCmd deletes Alert instances from the cluster
var deleteAlertCmd = &cobra.Command{
	Use:           "alert NAME -n NAMESPACE",
	Example:       "synopsysctl delete alert <name> -n <namespace>",
	Short:         "Delete an Alert instances",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			cmd.Help()
			return fmt.Errorf("this command takes 1 argument, but got %+v", len(args))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		alertName := args[0]
		helmReleaseName := fmt.Sprintf("%s%s", alertName, AlertPostSuffix)

		// Delete the Secrets
		helmRelease, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
			return fmt.Errorf("failed to get Alert values: %+v", cleanErrorMsg)
		}

		var name interface{}
		var ok bool
		if name, ok = helmRelease.Config["webserverCustomCertificatesSecretName"]; ok {
			if err := util.DeleteSecret(kubeClient, namespace, name.(string)); err != nil {
				return fmt.Errorf("failed to delete Alert custom certiface secret: %+v", err)
			}
		}
		if name, ok = helmRelease.Config["javaKeystoreSecretName"]; ok {
			if err := util.DeleteSecret(kubeClient, namespace, name.(string)); err != nil {
				return fmt.Errorf("failed to delete Alert javaKeystore secret: %+v", err)
			}
		}

		// Delete Alert Resources
		err = util.DeleteWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
			return fmt.Errorf("failed to delete Alert resources: %+v", cleanErrorMsg)
		}

		labelSelector := fmt.Sprintf("app=%s, name=%s", util.AlertName, alertName)
		svcs, err := util.ListServices(kubeClient, namespace, labelSelector)
		if err != nil {
			return fmt.Errorf("failed to list services: %+v", err)
		}
		for _, svc := range svcs.Items {
			if strings.HasSuffix(svc.Name, "-exposed") {
				if err := util.DeleteService(kubeClient, namespace, svc.Name); !k8serrors.IsNotFound(err) {
					return fmt.Errorf("failed to delete the Alert exposed service: %+v", err)
				}
			}
		}

		pvcs, err := util.ListPVCs(kubeClient, namespace, labelSelector)
		if err != nil {
			return fmt.Errorf("failed to list PVCs: %+v", err)
		}
		for _, pvc := range pvcs.Items {
			if err := util.DeletePVC(kubeClient, namespace, pvc.Name); !k8serrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete PVC '%s': %+v", pvc.Name, err)
			}
		}

		log.Infof("Alert has been successfully Deleted!")
		return nil
	},
}

// deleteBlackDuckCmd deletes Black Duck instances from the cluster
var deleteBlackDuckCmd = &cobra.Command{
	Use:           "blackduck NAME -n NAMESPACE",
	Example:       "synopsysctl delete blackduck <name> -n <namespace>",
	Short:         "Delete a Black Duck instances",
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
		err := util.DeleteWithHelm3(args[0], namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to delete Blackduck resources: %+v", err)
		}

		// delete secret
		secrets := []string{"webserver-certificate", "proxy-certificate", "auth-custom-ca"}
		for _, v := range secrets {
			if err := util.DeleteSecret(kubeClient, namespace, fmt.Sprintf("%s-%s-%s", args[0], util.BlackDuckName, v)); err != nil && !k8serrors.IsNotFound(err) {
				return fmt.Errorf("couldn't delete secret '%s' in namespace '%s' due to %+v", v, namespace, err)
			}
		}

		labelSelector := fmt.Sprintf("app=%s, name=%s", util.BlackDuckName, args[0])
		// delete exposed service
		svcs, err := util.ListServices(kubeClient, namespace, labelSelector)
		if err != nil {
			return fmt.Errorf("couldn't list services in namespace '%s' due to %+v", namespace, err)
		}
		for _, svc := range svcs.Items {
			if strings.HasSuffix(svc.Name, "-exposed") {
				if err := util.DeleteService(kubeClient, namespace, svc.Name); err != nil && !k8serrors.IsNotFound(err) {
					return fmt.Errorf("couldn't delete service '%s' in namespace '%s' due to %+v", svc.Name, namespace, err)
				}
			}
		}

		// delete PVC
		pvcs, err := util.ListPVCs(kubeClient, namespace, labelSelector)
		if err != nil {
			return fmt.Errorf("couldn't list pvc in namespace '%s' due to %+v", namespace, err)
		}
		for _, pvc := range pvcs.Items {
			if err := util.DeletePVC(kubeClient, namespace, pvc.Name); err != nil && !k8serrors.IsNotFound(err) {
				return fmt.Errorf("couldn't delete pvc '%s' in namespace '%s' due to %+v", pvc.Name, namespace, err)
			}
		}

		// delete route
		isOpenShift := util.IsOpenshift(kubeClient)
		if isOpenShift {
			routeName := util.GetResourceName(args[0], util.BlackDuckName, "")
			routeClient := util.GetRouteClient(restconfig, kubeClient, namespace)
			if _, err = util.GetRoute(routeClient, namespace, routeName); err == nil {
				err = util.DeleteRoute(routeClient, namespace, routeName)
				if err != nil {
					return fmt.Errorf("unable to delete Black Duck webserver route due to %+v", err)
				}
			}
		}

		log.Infof("Black Duck has been successfully Deleted!")
		return nil
	},
}

// deleteOpsSightCmd deletes an OpsSight instance from the cluster
var deleteOpsSightCmd = &cobra.Command{
	Use:           "opssight NAME -n NAMESPACE",
	Example:       "synopsysctl delete opssight <name> -n <namespace>",
	Short:         "Delete an OpsSight instances",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			cmd.Help()
			return fmt.Errorf("this command takes 1 argument but got %+v", len(args))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		// TODO Delete any initial resources...

		// Delete Opssight Resources
		err := util.DeleteWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to delete OpsSight resources: %+v", err)
		}

		log.Infof("OpsSight has been successfully Deleted!")
		return nil
	},
}

// deletePolarisCmd deletes a Polaris instance
var deletePolarisCmd = &cobra.Command{
	Use:           "polaris -n NAMESPACE",
	Example:       "synopsysctl delete polaris -n <namespace>",
	Short:         "Delete a Polaris instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		// Check the Number of Arguments
		if len(args) != 0 {
			cmd.Help()
			return fmt.Errorf("this command takes 0 arguments, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delete Polaris Resources
		err := util.DeleteWithHelm3(polarisName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to delete Polaris resources: %+v", err)
		}

		log.Infof("Polaris has been successfully Deleted!")
		return nil
	},
}

// deletePolarisReportingCmd deletes a Polaris-Reporting instance
var deletePolarisReportingCmd = &cobra.Command{
	Use:           "polaris-reporting -n NAMESPACE",
	Example:       "synopsysctl delete polaris-reportinng -n <namespace>",
	Short:         "Delete a Polaris-Reporting instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		// Check the Number of Arguments
		if len(args) != 0 {
			cmd.Help()
			return fmt.Errorf("this command takes 0 arguments, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get Secret For the GCP Key
		gcpServiceAccountSecrets, err := polarisreporting.GetPolarisReportingSecrets(namespace, "EMPTY_DATA")
		if err != nil {
			return fmt.Errorf("failed to generate GCP Service Account Secrets: %+v", err)
		}

		// Delete the Secret
		err = KubectlDeleteRuntimeObjects(gcpServiceAccountSecrets)
		if err != nil {
			return fmt.Errorf("failed to delete the gcpServiceAccount Secrets: %s", err)
		}

		// Delete Polaris-Reporting Resources
		err = util.DeleteWithHelm3(polarisReportingName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to delete Polaris-Reporting resources: %+v", err)
		}

		log.Infof("Polaris-Reporting has been successfully Deleted!")
		return nil
	},
}

// deleteBDBACmd deletes a BDBA instance
var deleteBDBACmd = &cobra.Command{
	Use:           "bdba -n NAMESPACE",
	Example:       "synopsysctl delete bdba -n <namespace>",
	Short:         "Delete a BDBA instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		// Check the Number of Arguments
		if len(args) != 0 {
			cmd.Help()
			return fmt.Errorf("this command takes 0 arguments, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delete Resources
		err := util.DeleteWithHelm3(bdbaName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to delete BDBA resources: %+v", err)
		}

		log.Infof("BDBA has been successfully Deleted!")
		return nil
	},
}

func init() {
	// deletePolarisReportingCobraHelper = *polarisreporting.NewArgsFromCobraFlags()

	//(PassCmd) deleteCmd.DisableFlagParsing = true // lets deleteCmd pass flags to kube/oc
	rootCmd.AddCommand(deleteCmd)

	// Add Delete Alert Command
	deleteAlertCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(deleteBlackDuckCmd.Flags(), "namespace")
	deleteCmd.AddCommand(deleteAlertCmd)

	// Add Delete Black Duck Command
	deleteBlackDuckCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(deleteBlackDuckCmd.Flags(), "namespace")
	deleteCmd.AddCommand(deleteBlackDuckCmd)

	// Add Delete OpsSight Command
	deleteOpsSightCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(deleteBDBACmd.Flags(), "namespace")
	deleteCmd.AddCommand(deleteOpsSightCmd)

	// Add Delete Polaris Command
	deletePolarisCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	deletePolarisCmd.Flags().BoolVarP(&promptAnswerYes, "yes", "y", promptAnswerYes, "Automatic yes to prompts")
	deleteCmd.AddCommand(deletePolarisCmd)

	// Add Delete Polaris-Reporting Command
	deletePolarisReportingCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(deletePolarisReportingCmd.Flags(), "namespace")
	deleteCmd.AddCommand(deletePolarisReportingCmd)

	// Add Delete BDBA Command
	deleteBDBACmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(deleteBDBACmd.Flags(), "namespace")
	deleteCmd.AddCommand(deleteBDBACmd)
}
