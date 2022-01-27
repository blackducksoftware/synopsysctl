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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	horizonapi "github.com/blackducksoftware/horizon/pkg/api"
	"github.com/blackducksoftware/horizon/pkg/components"
	"github.com/blackducksoftware/synopsysctl/pkg/alert"
	alertctl "github.com/blackducksoftware/synopsysctl/pkg/alert"
	"github.com/blackducksoftware/synopsysctl/pkg/bdba"
	blackduck "github.com/blackducksoftware/synopsysctl/pkg/blackduck"
	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	opssight "github.com/blackducksoftware/synopsysctl/pkg/opssight"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/release"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Update Command ResourceCtlSpecBuilders
var updateAlertCobraHelper alert.HelmValuesFromCobraFlags
var updateBlackDuckCobraHelper blackduck.HelmValuesFromCobraFlags
var updateOpsSightCobraHelper opssight.HelmValuesFromCobraFlags
var updateBDBACobraHelper bdba.HelmValuesFromCobraFlags

// updateCmd provides functionality to update/upgrade features of
// Synopsys resources
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a Synopsys resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("must specify a sub-command")
	},
}

/*
Update Alert Commands
*/

// updateAlertCmd updates an Alert instance
var updateAlertCmd = &cobra.Command{
	Use:           "alert NAME",
	Example:       "synopsysctl update alert <name>  -n <namespace> --port 80",
	Short:         "Update an Alert instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			cmd.Help()
			return fmt.Errorf("this command takes 1 argument but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		alertName := args[0]
		helmReleaseName := fmt.Sprintf("%s%s", alertName, globals.AlertPostSuffix)

		// TODO verity we can download the chart
		isOperatorBased := false
		instance, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
		if err != nil {
			isOperatorBased = true
		}

		if cmd.Flag("version").Changed {
			ok, err := util.IsNotDefaultVersionGreaterThanOrEqualTo(cmd.Flag("version").Value.String(), 5, 3, 1)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("updating of Alert instance is only suported for version 5.3.1 and above")
			}
		}

		if !isOperatorBased && instance != nil {
			// Update the Helm Chart Location
			globals.AlertVersion = util.GetValueFromRelease(instance, []string{"alert", "imageTag"}).(string)
			if cmd.Flags().Lookup("version").Changed {
				globals.AlertVersion = cmd.Flags().Lookup("version").Value.String()
			}
			err = UpdateHelmChartLocation(cmd.Flags(), globals.AlertChartName, globals.AlertVersion, &globals.AlertChartRepository)
			if err != nil {
				return fmt.Errorf("failed to set the app resources location due to %+v", err)
			}
			err = updateAlertHelmBased(cmd, helmReleaseName, alertName)
		} else if isOperatorBased {
			versionFlag := cmd.Flag("version")
			if !versionFlag.Changed {
				return fmt.Errorf("you must upgrade this Alert version with --version to use this synopsysctl binary")
			}
			// // TODO: Make sure 6.0.0 is the correct Chart Version for Alert
			// isGreaterThanOrEqualTo, err := util.IsNotDefaultVersionGreaterThanOrEqualTo(versionFlag.Value.String(), 6, 0, 0)
			// if err != nil {
			// 	return fmt.Errorf("failed to compare version: %+v", err)
			// }
			// if !isGreaterThanOrEqualTo {
			// 	return fmt.Errorf("you must upgrade this Alert to version 6.0.0 or after in order to use this synopsysctl binary - you gave version %+v", versionFlag.Value.String())
			// }
			err = updateAlertOperatorBased(cmd, helmReleaseName, alertName)
		}
		if err != nil {
			return err
		}

		log.Infof("Alert has been successfully Updated in namespace '%s'!", namespace)

		return nil
	},
}

func updateAlertHelmBased(cmd *cobra.Command, helmReleaseName string, alertName string) error {
	// Set flags from the current release in the updateAlertCobraHelper
	helmRelease, err := util.GetWithHelm3(helmReleaseName, namespace, kubeConfigPath)
	if err != nil {
		cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
		return fmt.Errorf("failed to get previous user defined values: %+v", cleanErrorMsg)
	}
	updateAlertCobraHelper.SetArgs(helmRelease.Config)

	// Update Helm Values with flags
	helmValuesMap, err := updateAlertCobraHelper.GenerateHelmFlagsFromCobraFlags(cmd.Flags())
	if err != nil {
		return err
	}

	if cmd.Flag("version").Changed {
		// if greater than or equal to 5.0.0, then copy PUBLIC_HUB_WEBSERVER_HOST to ALERT_HOSTNAME and PUBLIC_HUB_WEBSERVER_PORT to ALERT_SERVER_PORT
		// and delete PUBLIC_HUB_WEBSERVER_HOST and PUBLIC_HUB_WEBSERVER_PORT from the environs. In future, we need to request the customer to use the new params
		helmValuesMapAlertData := helmValuesMap["alert"].(map[string]interface{})
		oldAlertVersion := helmValuesMapAlertData["imageTag"].(string)
		isGreaterThanOrEqualTo, err := util.IsNotDefaultVersionGreaterThanOrEqualTo(oldAlertVersion, 5, 0, 0)
		if err != nil {
			return fmt.Errorf("failed to check Alert version: %+v", err)
		}
		if isGreaterThanOrEqualTo && helmValuesMap["environs"] != nil {
			maps := helmValuesMap["environs"].(map[string]interface{})
			isChanged := false
			if _, ok := maps["PUBLIC_HUB_WEBSERVER_HOST"]; ok {
				if _, ok1 := maps["ALERT_HOSTNAME"]; !ok1 {
					maps["ALERT_HOSTNAME"] = maps["PUBLIC_HUB_WEBSERVER_HOST"]
					isChanged = true
				}
				delete(maps, "PUBLIC_HUB_WEBSERVER_HOST")
			}

			if _, ok := maps["PUBLIC_HUB_WEBSERVER_PORT"]; ok {
				if _, ok1 := maps["ALERT_SERVER_PORT"]; !ok1 {
					maps["ALERT_SERVER_PORT"] = maps["PUBLIC_HUB_WEBSERVER_PORT"]
					isChanged = true
				}
				delete(maps, "PUBLIC_HUB_WEBSERVER_PORT")
			}

			if isChanged {
				util.SetHelmValueInMap(helmValuesMap, []string{"environs"}, maps)
			}
		}
	}

	// Get secrets for Alert
	certificateFlag := cmd.Flag("certificate-file-path")
	certificateKeyFlag := cmd.Flag("certificate-key-file-path")
	if certificateFlag.Changed && certificateKeyFlag.Changed {
		certificateData, err := util.ReadFileData(certificateFlag.Value.String())
		if err != nil {
			log.Fatalf("failed to read certificate file: %+v", err)
		}

		certificateKeyData, err := util.ReadFileData(certificateKeyFlag.Value.String())
		if err != nil {
			log.Fatalf("failed to read certificate file: %+v", err)
		}
		customCertificateSecretName := "alert-custom-certificate"
		customCertificateSecret := alert.GetAlertCustomCertificateSecret(namespace, customCertificateSecretName, certificateData, certificateKeyData)
		util.SetHelmValueInMap(helmValuesMap, []string{"webserverCustomCertificatesSecretName"}, customCertificateSecretName)
		if _, err := kubeClient.CoreV1().Secrets(namespace).Create(&customCertificateSecret); err != nil {
			if k8serrors.IsAlreadyExists(err) {
				if _, err := kubeClient.CoreV1().Secrets(namespace).Update(&customCertificateSecret); err != nil {
					return fmt.Errorf("failed to update certificate secret: %+v", err)
				}
			} else {
				return fmt.Errorf("failed to create certificate secret: %+v", err)
			}
		}
	}
	javaKeystoreFlag := cmd.Flag("java-keystore-file-path")
	if javaKeystoreFlag.Changed {
		javaKeystoreData, err := util.ReadFileData(javaKeystoreFlag.Value.String())
		if err != nil {
			log.Fatalf("failed to read Java Keystore file: %+v", err)
		}
		javaKeystoreSecretName := "alert-java-keystore"
		javaKeystoreSecret := alert.GetAlertJavaKeystoreSecret(namespace, javaKeystoreSecretName, javaKeystoreData)
		util.SetHelmValueInMap(helmValuesMap, []string{"javaKeystoreSecretName"}, javaKeystoreSecretName)
		if _, err := kubeClient.CoreV1().Secrets(namespace).Create(&javaKeystoreSecret); err != nil {
			if k8serrors.IsAlreadyExists(err) {
				if _, err := kubeClient.CoreV1().Secrets(namespace).Update(&javaKeystoreSecret); err != nil {
					return fmt.Errorf("failed to update javakeystore secret: %+v", err)
				}
			} else {
				return fmt.Errorf("failed to create javakeystore secret: %+v", err)
			}
		}
	}

	// Expose Services for Alert
	err = alert.CRUDServiceOrRoute(restconfig, kubeClient, namespace, alertName, helmValuesMap["exposeui"], helmValuesMap["exposedServiceType"], cmd.Flags().Lookup("expose-ui").Changed)
	if err != nil {
		return fmt.Errorf("failed to update exposed service due to %+v", err)
	}

	// Update Alert Resources
	err = util.UpdateWithHelm3(helmReleaseName, namespace, globals.AlertChartRepository, helmValuesMap, kubeConfigPath)
	if err != nil {
		cleanErrorMsg := cleanAlertHelmError(err.Error(), helmReleaseName, alertName)
		return fmt.Errorf("failed to update Alert resources due to %+v", cleanErrorMsg)
	}
	return nil
}

func updateAlertOperatorBased(cmd *cobra.Command, newReleaseName string, alertName string) error {
	operatorNamespace := namespace
	isClusterScoped := util.GetClusterScope(apiExtensionClient)
	if isClusterScoped {
		opNamespace, err := util.GetOperatorNamespace(kubeClient, metav1.NamespaceAll)
		if err != nil {
			return err
		}
		if len(opNamespace) > 1 {
			return fmt.Errorf("more than 1 Synopsys Operator found in your cluster")
		}
		operatorNamespace = opNamespace[0]
	}

	crdNamespace := namespace
	if isClusterScoped {
		crdNamespace = metav1.NamespaceAll
	}

	currAlert, err := util.GetAlert(alertClient, crdNamespace, alertName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting Alert '%s' in namespace '%s' due to %+v", alertName, crdNamespace, err)
	}

	if err := migrateAlert(currAlert, newReleaseName, operatorNamespace, crdNamespace, cmd.Flags()); err != nil {
		// TODO restart operator if migration failed?
		return err
	}
	return nil
}

// updateBlackDuckCmd updates a Black Duck instance
var updateBlackDuckCmd = &cobra.Command{
	Use:           "blackduck NAME -n NAMESPACE",
	Example:       "synopsyctl update blackduck <name> -n <namespace> --size medium",
	Short:         "Update a Black Duck instance",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("this command takes 1 argument, but got %+v", args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		blackDuckName := args[0]
		blackDuckNamespace := namespace

		isOperatorBased := false
		instance, err := util.GetWithHelm3(args[0], blackDuckNamespace, kubeConfigPath)
		if err != nil {
			isOperatorBased = true
		}

		if !isOperatorBased && instance != nil {
			// Update the Helm Chart Location
			globals.BlackDuckVersion = util.GetValueFromRelease(instance, []string{"imageTag"}).(string)
			if cmd.Flags().Lookup("version").Changed {
				globals.BlackDuckVersion = cmd.Flags().Lookup("version").Value.String()

				ok, err := util.IsVersionGreaterThanOrEqualTo(globals.BlackDuckVersion, 2020, time.April, 0)
				if err != nil {
					return err
				}

				if !ok {
					return fmt.Errorf("upgrade of Black Duck instance is only suported for version 2020.4.0 and above")
				}
			}
			err = UpdateHelmChartLocation(cmd.Flags(), globals.BlackDuckChartName, globals.BlackDuckVersion, &globals.BlackDuckChartRepository)
			if err != nil {
				return fmt.Errorf("failed to set the app resources location due to %+v", err)
			}

			oldVersion := util.GetValueFromRelease(instance, []string{"imageTag"}).(string)
			log.Debugf("old version: %+v", oldVersion)

			var sizeYAMLFileNameInChart string
			if cmd.Flag("size").Changed {
				sizeYAMLFileNameInChart = fmt.Sprintf("%s.yaml", cmd.Flag("size").Value.String())
			} else {
				if size, found := instance.Config["size"]; found && len(size.(string)) > 0 {
					sizeYAMLFileNameInChart = fmt.Sprintf("%s.yaml", size.(string))
				}
			}

			sizeYAMLFileNameInChart = strings.ToLower(sizeYAMLFileNameInChart)

			if len(sizeYAMLFileNameInChart) > 0 {
				sizeValuesFromChart, err := util.ConvertFilesFromChartToMap(blackDuckNamespace, kubeConfigPath, globals.BlackDuckChartRepository, sizeYAMLFileNameInChart)
				if err != nil {
					return err
				}
				instance.Config = util.MergeMaps(instance.Config, sizeValuesFromChart)
			}

			updateBlackDuckCobraHelper.SetArgs(instance.Config)
			helmValuesMap, err := updateBlackDuckCobraHelper.GenerateHelmFlagsFromCobraFlags(cmd.Flags())
			if err != nil {
				return err
			}

			secrets, err := blackduck.GetCertsFromFlagsAndSetHelmValue(args[0], blackDuckNamespace, cmd.Flags(), helmValuesMap)
			if err != nil {
				return err
			}

			// Create or update the secret based on the certificate/password file path is set
			isSecretUpdated := false
			for _, v := range secrets {
				if secret, err := util.GetSecret(kubeClient, blackDuckNamespace, v.Name); err == nil {
					secret.Data = v.Data
					secret.StringData = v.StringData
					if _, err := util.UpdateSecret(kubeClient, blackDuckNamespace, secret); err != nil {
						return fmt.Errorf("failed to update the %s secret due to %+v", v.Name, err)
					}
					log.Debugf("updated secret %s in namespace %s", secret.Name, blackDuckNamespace)
				} else {
					if _, err := kubeClient.CoreV1().Secrets(blackDuckNamespace).Create(&v); err != nil {
						return fmt.Errorf("failed to create the %s secret due to %+v", v.Name, err)
					}
				}
				isSecretUpdated = true
			}

			// Whenever the secrets are created/updated, delete the corresponding pods to input the created/updated secrets
			if isSecretUpdated {
				labelSelectors := []string{
					fmt.Sprintf("name=%s,component=authentication", blackDuckName),
					fmt.Sprintf("name=%s,component=bomengine", blackDuckName),
					fmt.Sprintf("name=%s,component=matchengine", blackDuckName),
					fmt.Sprintf("name=%s,component=jobrunner", blackDuckName),
					fmt.Sprintf("name=%s,component=registration", blackDuckName),
					fmt.Sprintf("name=%s,component=scan", blackDuckName),
					fmt.Sprintf("name=%s,component=webapp-logstash", blackDuckName),
					fmt.Sprintf("name=%s,component=webserver", blackDuckName),
				}

				for _, labelSelector := range labelSelectors {
					podList, err := util.ListPodsWithLabels(kubeClient, blackDuckNamespace, labelSelector)
					if err != nil {
						log.Warnf("unable to list pods using %s label selector due to %+v", labelSelector, err)
						continue
					}
					for _, pod := range podList.Items {
						err = util.DeletePod(kubeClient, blackDuckNamespace, pod.Name)
						if err != nil {
							return fmt.Errorf("unable to delete %s pod due to %+v", pod.Name, err)
						}
					}
				}
			}

			// Update Security Context Permissions
			newVals := util.MergeMaps(instance.Chart.Values, helmValuesMap)
			err = runBlackDuckFileOwnershipJobs(blackDuckName, blackDuckNamespace, oldVersion, newVals, cmd.Flags())
			if err != nil {
				return fmt.Errorf("failed to update File Ownerships in PVs: %+v", err)
			}

			// validations
			err = createBlackDuckCobraHelper.VerifyChartVersionSupportsChangedFlags(cmd.Flags(), globals.BlackDuckVersion)
			if err != nil {
				return err
			}

			// Deploy resources
			if err := util.UpdateWithHelm3(blackDuckName, blackDuckNamespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath); err != nil {
				return fmt.Errorf("failed to update Black Duck due to %+v", err)
			}

			err = blackduck.CRUDServiceOrRoute(restconfig, kubeClient, blackDuckNamespace, args[0], helmValuesMap["exposeui"], helmValuesMap["exposedServiceType"], cmd.Flags().Lookup("expose-ui").Changed)
			if err != nil {
				return err
			}

		} else if isOperatorBased {
			if !cmd.Flag("version").Changed {
				return fmt.Errorf("you must upgrade this Blackduck version with --version 2020.4.0 and above to use this synopsysctl binary")
			}
			ok, err := util.IsVersionGreaterThanOrEqualTo(cmd.Flag("version").Value.String(), 2020, time.April, 0)
			if err != nil {
				return err
			}

			if !ok {
				return fmt.Errorf("migration is only suported for version 2020.4.0 and above")
			}

			operatorNamespace := namespace
			isClusterScoped := util.GetClusterScope(apiExtensionClient)
			if isClusterScoped {
				opNamespace, err := util.GetOperatorNamespace(kubeClient, metav1.NamespaceAll)
				if err != nil {
					return err
				}
				if len(opNamespace) > 1 {
					return fmt.Errorf("more than 1 Synopsys Operator found in your cluster")
				}
				operatorNamespace = opNamespace[0]
			}

			blackDuckName := args[0]
			crdNamespace := namespace
			if isClusterScoped {
				crdNamespace = metav1.NamespaceAll
			}

			currBlackDuck, err := util.GetBlackduck(blackDuckClient, crdNamespace, blackDuckName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("error getting Black Duck '%s' in namespace '%s' due to %+v", blackDuckName, crdNamespace, err)
			}
			if err := migrate(currBlackDuck, operatorNamespace, crdNamespace, cmd.Flags()); err != nil {
				return err
			}
		}

		log.Infof("Black Duck has been successfully Updated in namespace '%s'!", blackDuckNamespace)
		return nil
	},
}

func runBlackDuckFileOwnershipJobs(blackDuckName, blackDuckNamespace, oldVersion string, helmReleaseValues map[string]interface{}, flags *pflag.FlagSet) error {
	newVersion := util.GetHelmValueFromMap(helmReleaseValues, []string{"imageTag"}).(string)
	currState := util.GetHelmValueFromMap(helmReleaseValues, []string{"status"}).(string)
	persistentStroage := util.GetHelmValueFromMap(helmReleaseValues, []string{"enablePersistentStorage"}).(bool)

	// Update the File Owernship in Persistent Volumes if Security Context changes are needed
	oldVersionIsGreaterThanOrEqualv2019x12x0, err := util.IsVersionGreaterThanOrEqualTo(oldVersion, 2019, time.December, 0)
	if err != nil {
		return err
	}
	newVersionIsGreaterThanOrEqualv2019x12x0, err := util.IsVersionGreaterThanOrEqualTo(newVersion, 2019, time.December, 0)
	if err != nil {
		return err
	}
	if !newVersionIsGreaterThanOrEqualv2019x12x0 && flags.Changed("security-context-file-path") {
		return fmt.Errorf("security contexts from --security-context-file-path cannot be set for versions before 2019.12.0, you're using version %s", newVersion)
	}
	if util.IsOpenshift(kubeClient) && flags.Changed("security-context-file-path") {
		return fmt.Errorf("cannot set security contexts with --security-context-file-path in an Openshift environment")
	}

	// case: Security Contexts are set in an old version and then upgrade to a version that requires changes
	bdUpdatedToVersionWithSecurityContexts := flags.Lookup("version").Changed && (!oldVersionIsGreaterThanOrEqualv2019x12x0 && newVersionIsGreaterThanOrEqualv2019x12x0)

	// case: Black Duck will be restarted during update and no changes to PVs are needed
	bdUpdatedToVersionWithSecurityContextsAndNoPersistentStorage := bdUpdatedToVersionWithSecurityContexts && !persistentStroage

	// case: Security Contexts are changed and it's a version with support for security contexts
	bdSecurityContextsWereChanged := flags.Lookup("security-context-file-path").Changed && newVersionIsGreaterThanOrEqualv2019x12x0

	if (bdUpdatedToVersionWithSecurityContexts || bdSecurityContextsWereChanged) && !bdUpdatedToVersionWithSecurityContextsAndNoPersistentStorage && !util.IsOpenshift(kubeClient) {
		// Stop the BlackDuck instance
		if strings.ToUpper(currState) != "STOPPED" {
			log.Infof("stopping Black Duck to apply Security Context changes")
			tmpValuesMap := make(map[string]interface{})
			err = util.DeepCopyHelmValuesMap(helmReleaseValues, tmpValuesMap) // don't update actual values so the Update Command will restart the instance
			if err != nil {
				return fmt.Errorf("failed to deep copy values for stopping Black Duck: %+v", err)
			}
			util.SetHelmValueInMap(tmpValuesMap, []string{"status"}, "Stopped")
			err = util.UpdateWithHelm3(blackDuckName, namespace, globals.BlackDuckChartRepository, tmpValuesMap, kubeConfigPath)
			if err != nil {
				return fmt.Errorf("failed to create Blackduck resources: %+v", err)
			}
			// Wait for Black Duck to Stop
			log.Infof("waiting for Black Duck to stop...")
			waitCount := 0
			for {
				// ... wait for the Black Duck to stop
				pods, err := util.ListPodsWithLabels(kubeClient, blackDuckNamespace, fmt.Sprintf("app=blackduck,name=%s", blackDuckName))
				if err != nil {
					return errors.Wrap(err, "failed to list pods to stop Black Duck for setting group ownership")
				}
				// Break if there are no pods or if all jobs are Succeeded
				if len(pods.Items) == 0 {
					log.Debugf("Black Duck is stopped - no remaining pods in namespace %+v", blackDuckNamespace)
					break
				} else {
					foundAllSucceeded := true
					for _, po := range pods.Items {
						if po.Status.Phase != corev1.PodSucceeded {
							foundAllSucceeded = false
						}
					}
					if foundAllSucceeded {
						log.Debugf("Black Duck is stopped - no remaining pods and all jobs are completed in namespace %+v", blackDuckNamespace)
						break
					}
				}
				time.Sleep(time.Second * 5)
				waitCount = waitCount + 1
				if waitCount%5 == 0 {
					log.Debugf("waiting for Black Duck to stop - %d pods remaining", len(pods.Items))
				}
			}
		}
		// TODO delete job and its pod

		// Get a list of Persistent Volumes based on Persistent Volume Claims
		pvcList, err := util.ListPVCs(kubeClient, blackDuckNamespace, fmt.Sprintf("app=blackduck,component=pvc,name=%s", blackDuckName))
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list PVCs to update the group ownership"))
		}

		// Map the Persistent Volume to the respective Security Context File Ownership value
		// - if security contexts are not provided then this map will be empty
		pvcNameToFileOwnershipMap := map[string]int64{}
		pvcIDNameToHelmPath := map[string][]string{
			"blackduck-postgres":         {"postgres", "podSecurityContext"},
			"blackduck-authentication":   {"authentication", "podSecurityContext"},
			"blackduck-cfssl":            {"cfssl", "podSecurityContext"},
			"blackduck-registration":     {"registration", "podSecurityContext"},
			"blackduck-webapp":           {"webapp", "podSecurityContext"},
			"blackduck-logstash":         {"logstash", "securityContext"},
			"blackduck-uploadcache-data": {"uploadcache", "podSecurityContext"},
		}
		log.Infof("checking Persistent Volumes...")
		for _, pvc := range pvcList.Items {
			r, _ := regexp.Compile("blackduck-.*")
			pvcNameKey := r.FindString(pvc.Name) // removes the "<blackduckName>-" from the PvcName

			pvcHelmPath := []string{pvcNameKey, "podSecurityContext"}          // default path for new pods
			if newPathToHelmValue, ok := pvcIDNameToHelmPath[pvcNameKey]; ok { // override the security if it's present in the list
				pvcHelmPath = newPathToHelmValue
			}

			scInterface := util.GetHelmValueFromMap(helmReleaseValues, pvcHelmPath)
			if scInterface != nil {
				sc := scInterface.(map[string]interface{})
				// if runAsUser exists, add the File Ownership value to the map
				if val, ok := sc["runAsUser"]; ok {
					pvcNameToFileOwnershipMap[pvc.Name] = val.(int64)
				}
			}
		}

		// Update the Persistent Volumes that have a File Ownership values in the map
		if len(pvcNameToFileOwnershipMap) > 0 { // skip if no File Ownerships are set
			log.Infof("updating file ownership in Persistent Volumes...")
			// Create Jobs to set the File Owernship in the Persistent Volume
			var wg sync.WaitGroup
			wg.Add(len(pvcNameToFileOwnershipMap))
			for pvcName, ownership := range pvcNameToFileOwnershipMap {
				log.Infof("creating file owernship job to set ownership value to '%d' in PV '%s'", ownership, pvcName)
				go setBlackDuckFileOwnershipJob(blackDuckNamespace, blackDuckName, pvcName, ownership, &wg)
			}
			log.Infof("waiting for file owernship jobs to finish...")
			wg.Wait()
			if len(pvcNameToFileOwnershipMap) != len(pvcList.Items) {
				log.Warnf("a Job was not created for every Persistent Volume in namespace '%s'", blackDuckNamespace)
			}
		}

		// // Restart the Black Duck instance
		// if strings.ToUpper(currState) != "STOPPED" {
		// 	log.Infof("restarting Black Duck")
		// 	tmpValuesMap := make(map[string]interface{})
		// 	util.SetHelmValueInMap(tmpValuesMap, []string{"status"}, currState)
		// 	if err := util.UpdateWithHelm3(blackDuckName, namespace, globals.BlackDuckChartRepository, tmpValuesMap, kubeConfigPath); err != nil {
		// 		return fmt.Errorf("failed to restart BlackDuck after setting File Ownerships: %+v", err)
		// 	}
		// }
	}
	return nil
}

// setBlackDuckFileOwnershipJob that sets the Owner of the files
func setBlackDuckFileOwnershipJob(namespace string, name string, pvcName string, ownership int64, wg *sync.WaitGroup) error {
	busyBoxImage := globals.DefaultBusyBoxImage
	volumeClaim := components.NewPVCVolume(horizonapi.PVCVolumeConfig{PVCName: pvcName})
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("set-file-ownership-%s", pvcName),
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "set-file-ownership-container",
							Image:   busyBoxImage,
							Command: []string{"chown", "-R", fmt.Sprintf("%d", ownership), "/setfileownership"},
							VolumeMounts: []corev1.VolumeMount{
								{Name: pvcName, MountPath: "/setfileownership"},
							},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
					Volumes: []corev1.Volume{
						{Name: pvcName, VolumeSource: volumeClaim.VolumeSource},
					},
				},
			},
		},
	}
	defer wg.Done()

	job, err := kubeClient.BatchV1().Jobs(namespace).Create(job)
	if err != nil {
		panic(fmt.Sprintf("failed to create job for setting group ownership due to %s", err))
	}

	timeout := time.NewTimer(30 * time.Minute)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("failed to set the group ownership of files for PV '%s' in namespace '%s'", pvcName, namespace)

		case <-ticker.C:
			job, err = kubeClient.BatchV1().Jobs(job.Namespace).Get(job.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if job.Status.Succeeded > 0 {
				log.Infof("successfully set the group ownership of files for PV '%s' in namespace '%s'", pvcName, namespace)

				// Delete the Job
				deletePodsPolicy := metav1.DeletePropagationBackground
				err = kubeClient.BatchV1().Jobs(job.Namespace).Delete(job.Name, &metav1.DeleteOptions{PropagationPolicy: &deletePodsPolicy})
				if err != nil {
					log.Warnf("failed to delete Security Context Jobs '%s' due to %s", job.Name, err)
				}
				return nil
			}
		}
	}
}

// updateBlackDuckMasterKeyCmd create new Black Duck master key for source code upload in the cluster
var updateBlackDuckMasterKeyCmd = &cobra.Command{
	Use:           "masterkey BLACK_DUCK_NAME DIRECTORY_PATH_OF_STORED_MASTER_KEY NEW_SEAL_KEY -n NAMESPACE",
	Example:       "synopsysctl update blackduck masterkey <name> <directory path of the stored master key> <new seal key> -n <namespace>",
	Short:         "Update the master key of the Black Duck instance that is used for source code upload",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 3 {
			cmd.Help()
			return fmt.Errorf("this command takes 3 arguments, but got %+v", args)
		}

		if len(args[2]) != 32 {
			return fmt.Errorf("new seal key should be of length 32")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		release, err := util.GetWithHelm3(args[0], namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance %s in namespace %s", args[0], namespace)
		}
		if err := updateMasterKey(namespace, args[0], args[1], args[2], false, release, cmd); err != nil {
			return err
		}
		return nil
	},
}

// updateBlackDuckMasterKeyNativeCmd create new Black Duck master key for source code upload in the cluster
var updateBlackDuckMasterKeyNativeCmd = &cobra.Command{
	Use:           "native NAME DIRECTORY_PATH_OF_STORED_MASTER_KEY NEW_SEAL_KEY -n NAMESPACE",
	Example:       "synopsysctl update blackduck masterkey native <name> <directory path of the stored master key> <new seal key> -n <namespace>",
	Short:         "Update the master key of the Black Duck instance that is used for source code upload",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 3 {
			cmd.Help()
			return fmt.Errorf("this command takes 3 arguments, but got %+v", args)
		}

		if len(args[2]) != 32 {
			return fmt.Errorf("new seal key should be of length 32")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := updateMasterKey(namespace, args[0], args[1], args[2], true, nil, nil); err != nil {
			return err
		}
		return nil
	},
}

// updateMasterKey updates the master key and encoded with new seal key
func updateMasterKey(namespace string, name string, oldMasterKeyFilePath string, newSealKey string, isNative bool, release *release.Release, cmd *cobra.Command) error {

	// getting the seal key secret to retrieve the seal key
	secret, err := util.GetSecret(kubeClient, namespace, fmt.Sprintf("%s-blackduck-upload-cache", name))
	if err != nil {
		return fmt.Errorf("unable to find Seal key secret (%s-blackduck-upload-cache) in namespace '%s' due to %+v", name, namespace, err)
	}

	log.Infof("updating Black Duck '%s's master key in namespace '%s'...", name, namespace)

	// read the old master key
	fileName := filepath.Join(oldMasterKeyFilePath, fmt.Sprintf("%s-%s.key", namespace, name))
	masterKey, err := ioutil.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("error reading the master key from file '%s' due to %+v", fileName, err)
	}

	// Filter the upload cache pod to get the root key using the seal key
	uploadCachePod, err := util.FilterPodByNamePrefixInNamespace(kubeClient, namespace, util.GetResourceName(name, util.BlackDuckName, "uploadcache"))
	if err != nil {
		return fmt.Errorf("unable to filter the upload cache pod in namespace '%s' due to %+v", namespace, err)
	}

	// Create the exec into Kubernetes pod request
	req := util.CreateExecContainerRequest(kubeClient, uploadCachePod, "/bin/sh")

	_, err = util.ExecContainer(restconfig, req, []string{fmt.Sprintf(`curl -X PUT --header "X-SEAL-KEY:%s" -H "X-MASTER-KEY:%s" https://localhost:9444/api/internal/recovery --cert /opt/blackduck/hub/blackduck-upload-cache/security/blackduck-upload-cache-server.crt --key /opt/blackduck/hub/blackduck-upload-cache/security/blackduck-upload-cache-server.key --cacert /opt/blackduck/hub/blackduck-upload-cache/security/root.crt`, base64.StdEncoding.EncodeToString([]byte(newSealKey)), masterKey)})
	if err != nil {
		return fmt.Errorf("unable to exec into upload cache pod in namespace '%s' due to %+v", namespace, err)
	}

	log.Infof("successfully updated the master key in the upload cache container of Black Duck '%s' in namespace '%s'", name, namespace)

	if isNative {
		// update the new seal key
		secret.Data["SEAL_KEY"] = []byte(newSealKey)
		_, err = util.UpdateSecret(kubeClient, namespace, secret)
		if err != nil {
			return fmt.Errorf("unable to update Seal key secret (%s-blackduck-upload-cache) in namespace '%s' due to %+v", name, namespace, err)
		}

		log.Infof("successfully updated the seal key secret for Black Duck '%s' in namespace '%s'", name, namespace)

		// delete the upload cache pod
		err = util.DeletePod(kubeClient, namespace, uploadCachePod.Name)
		if err != nil {
			return fmt.Errorf("unable to delete an upload cache pod in namespace '%s' due to %+v", namespace, err)
		}

		log.Infof("successfully deleted an upload cache pod for Black Duck '%s' in namespace '%s' to reflect the new seal key. Wait for upload cache pod to restart to resume the source code upload", name, namespace)
	} else {
		// Get the flags to set Helm values
		helmValuesMap := release.Config

		// Update the Helm Chart Location
		globals.BlackDuckVersion = util.GetValueFromRelease(release, []string{"imageTag"}).(string)
		err = UpdateHelmChartLocation(cmd.Flags(), globals.BlackDuckChartName, globals.BlackDuckVersion, &globals.BlackDuckChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// set the new seal key
		util.SetHelmValueInMap(helmValuesMap, []string{"sealKey"}, newSealKey)

		if err := util.UpdateWithHelm3(name, namespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath); err != nil {
			return err
		}

		// delete the upload cache pod. TODO: remove after the Black Duck is merged...
		err = util.DeletePod(kubeClient, namespace, uploadCachePod.Name)
		if err != nil {
			return fmt.Errorf("unable to delete an upload cache pod in namespace '%s' due to %+v", namespace, err)
		}

		log.Infof("successfully submitted updates to Black Duck '%s' in namespace '%s'. Wait for upload cache pod to restart to resume the source code upload", name, namespace)
	}
	return nil
}

// updateBlackDuckAddEnvironCmd adds an Environment Variable to a Black Duck instance
var updateBlackDuckAddEnvironCmd = &cobra.Command{
	Use:           "addenviron NAME (ENVIRON_NAME:ENVIRON_VALUE) -n NAMESPACE",
	Example:       "synopsysctl update blackduck addenviron <name> USE_ALERT:1 -n <namespace>",
	Short:         "Add an Environment Variable to a Black Duck instance",
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
		helmRelease, err := util.GetWithHelm3(args[0], namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("couldn't find instance %s in namespace %s", args[0], namespace)
		}

		helmValuesMap := helmRelease.Config

		// Update the Helm Chart Location
		globals.BlackDuckVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.BlackDuckVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.BlackDuckChartName, globals.BlackDuckVersion, &globals.BlackDuckChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		vals := strings.Split(args[1], ":")
		if len(vals) != 2 {
			return fmt.Errorf("%s is not valid - expecting NAME:VALUE", args[0])
		}
		log.Infof("updating Black Duck '%s' with environ '%s' in namespace '%s'...", args[0], args[1], namespace)

		util.SetHelmValueInMap(helmValuesMap, []string{"environs", vals[0]}, vals[1])

		if err := util.UpdateWithHelm3(args[0], namespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath); err != nil {
			return err
		}

		log.Infof("successfully submitted updates to Black Duck '%s' in namespace '%s'", args[0], namespace)
		return nil
	},
}

/*
Update OpsSight Commands
*/

// updateOpsSightCmd updates an OpsSight instance
var updateOpsSightCmd = &cobra.Command{
	Use:           "opssight NAME -n NAMESPACE",
	Example:       "synopsyctl update opssight <name> -n <namespace> --blackduck-max-count 2",
	Short:         "Update an OpsSight instance",
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

		// Set flags from the current release in the updateOpsSightCobraHelper
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		updateOpsSightCobraHelper.SetArgs(helmRelease.Config)

		// Update the Helm Chart Location
		globals.OpsSightVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.OpsSightVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, globals.OpsSightVersion, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Helm Values with flags
		helmValuesMap, err := updateOpsSightCobraHelper.GenerateHelmFlagsFromCobraFlags(cmd.Flags())
		if err != nil {
			return err
		}

		// Update any initial resources that were created...

		// Update OpsSight Resources
		err = util.UpdateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight resources due to %+v", err)
		}

		log.Infof("OpsSight has been successfully updated in namespace '%s'!", namespace)

		return nil
	},
}

// updateOpsSightExternalHostCmd updates an external host for an OpsSight intance's component
var updateOpsSightExternalHostCmd = &cobra.Command{
	Use:           "externalhost NAME SCHEME DOMAIN PORT USER PASSWORD SCANLIMIT -n NAMESPACE",
	Example:       "synopsysctl update opssight externalhost <name> scheme domain 80 user pass 50 -n <namespace>",
	Short:         "Update an external host for an OpsSight intance's component",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 7 {
			cmd.Help()
			return fmt.Errorf("this command takes 7 arguments")
		}
		// Check Host Port
		_, err := strconv.ParseInt(args[3], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid port number: '%s'", err)
		}
		// Check Host Scan Limit
		_, err = strconv.ParseInt(args[6], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid concurrent scan limit: %s", err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		scheme := args[1]
		domain := args[2]
		port := args[3]
		user := args[4]
		pass := args[5]
		scanLimit := args[6]

		// Get flags from the current release
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		helmValuesMap := helmRelease.Config

		// Update the Helm Chart Location
		globals.OpsSightVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.OpsSightVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, globals.OpsSightVersion, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Helm Values with External BlackDuck values
		currExternalBlackDucks := make([]map[string]interface{}, 0)
		if _, ok := helmValuesMap["externalBlackDuck"]; ok {
			currExternalBlackDucks = helmValuesMap["externalBlackDuck"].([]map[string]interface{})
		}
		hostPort, err := strconv.ParseInt(port, 0, 64)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight due to %+v", err)
		}
		hostScanLimit, err := strconv.ParseInt(scanLimit, 0, 64)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight due to %+v", err)
		}
		newBD := map[string]interface{}{
			"scheme":              scheme,
			"domain":              domain,
			"port":                int(hostPort),
			"user":                user,
			"password":            pass,
			"concurrentScanLimit": int(hostScanLimit),
		}
		newExternalBlackDucks := append(currExternalBlackDucks, newBD)
		util.SetHelmValueInMap(helmValuesMap, []string{"externalBlackDuck"}, newExternalBlackDucks)

		// Update OpsSight Resources
		err = util.UpdateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight resources due to %+v", err)
		}

		log.Infof("OpsSight has been successfully updated in namespace '%s'!", namespace)
		return nil
	},
}

// updateOpsSightExternalHostNativeCmd prints the Kubernetes resources with updates to an external host for an OpsSight intance's component
var updateOpsSightExternalHostNativeCmd = &cobra.Command{
	Use:           "externalhost NAME SCHEME DOMAIN PORT USER PASSWORD SCANLIMIT -n NAMESPACE",
	Example:       "synopsysctl update opssight externalhost native <name> scheme domain 80 user pass 50 -n <namespace>",
	Short:         "Print the Kubernetes resources with updates to an external host for an OpsSight intance's component",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 7 {
			cmd.Help()
			return fmt.Errorf("this command takes 7 arguments")
		}
		// Check Host Port
		_, err := strconv.ParseInt(args[3], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid port number: '%s'", err)
		}
		// Check Host Scan Limit
		_, err = strconv.ParseInt(args[6], 0, 64)
		if err != nil {
			return fmt.Errorf("invalid concurrent scan limit: %s", err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		scheme := args[1]
		domain := args[2]
		port := args[3]
		user := args[4]
		pass := args[5]
		scanLimit := args[6]

		// Get flags from the current release
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		helmValuesMap := helmRelease.Config

		// Update the Helm Chart Location
		globals.OpsSightVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.OpsSightVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, globals.OpsSightVersion, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Helm Values with External BlackDuck values
		currExternalBlackDucks := make([]map[string]interface{}, 0)
		if _, ok := helmValuesMap["externalBlackDuck"]; ok {
			currExternalBlackDucks = helmValuesMap["externalBlackDuck"].([]map[string]interface{})
		}
		hostPort, err := strconv.ParseInt(port, 0, 64)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight due to %+v", err)
		}
		hostScanLimit, err := strconv.ParseInt(scanLimit, 0, 64)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight due to %+v", err)
		}
		newBD := map[string]interface{}{
			"scheme":              scheme,
			"domain":              domain,
			"port":                int(hostPort),
			"user":                user,
			"password":            pass,
			"concurrentScanLimit": int(hostScanLimit),
		}
		newExternalBlackDucks := append(currExternalBlackDucks, newBD)
		util.SetHelmValueInMap(helmValuesMap, []string{"externalBlackDuck"}, newExternalBlackDucks)

		// Update OpsSight Resources
		err = util.UpdateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight resources due to %+v", err)
		}

		log.Infof("OpsSight has been successfully updated in namespace '%s'!", namespace)
		return nil
	},
}

// updateOpsSightAddRegistryCmd adds an internal registry to an OpsSight instance's ImageFacade
var updateOpsSightAddRegistryCmd = &cobra.Command{
	Use:           "registry NAME URL USER PASSWORD -n NAMESPACE",
	Example:       "synopsysctl update opssight registry <name> reg_url reg_username reg_password -n <namespace>",
	Short:         "Add an internal registry to an OpsSight instance's ImageFacade",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 4 {
			cmd.Help()
			return fmt.Errorf("this command takes 4 arguments")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		url := args[1]
		user := args[2]
		pass := args[3]

		// Get flags from the current release
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		helmValuesMap := helmRelease.Config

		// Update the Helm Chart Location
		globals.OpsSightVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.OpsSightVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, globals.OpsSightVersion, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Helm Values with Secured Registry values
		currRegistries := make([]map[string]interface{}, 0)
		if _, ok := helmValuesMap["securedRegistries"]; ok {
			currRegistries = helmValuesMap["securedRegistries"].([]map[string]interface{})
		}
		newRegistry := map[string]interface{}{
			"url":      url,
			"user":     user,
			"password": pass,
		}
		newRegistries := append(currRegistries, newRegistry)
		util.SetHelmValueInMap(helmValuesMap, []string{"securedRegistries"}, newRegistries)

		// Update OpsSight Resources
		err = util.UpdateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight resources due to %+v", err)
		}

		log.Infof("OpsSight has been successfully updated in namespace '%s'!", namespace)
		return nil
	},
}

// updateOpsSightAddRegistryNativeCmd prints the Kubernetes resources with updates from adding an internal registry to an OpsSight instance's ImageFacade
var updateOpsSightAddRegistryNativeCmd = &cobra.Command{
	Use:           "native NAME URL USER PASSWORD -n NAMESPACE",
	Example:       "synopsysctl update opssight registry native <name> reg_url reg_username reg_password -n <namespace>",
	Short:         "Print the Kubernetes resources with updates from adding an internal registry to an OpsSight instance's ImageFacade",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 4 {
			cmd.Help()
			return fmt.Errorf("this command takes 4 arguments")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opssightName := args[0]
		url := args[1]
		user := args[2]
		pass := args[3]

		// Get flags from the current release
		helmRelease, err := util.GetWithHelm3(opssightName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		helmValuesMap := helmRelease.Config

		// Update the Helm Chart Location
		globals.OpsSightVersion = util.GetValueFromRelease(helmRelease, []string{"imageTag"}).(string)
		if cmd.Flags().Lookup("version").Changed {
			globals.OpsSightVersion = cmd.Flags().Lookup("version").Value.String()
		}
		err = UpdateHelmChartLocation(cmd.Flags(), globals.OpsSightChartName, globals.OpsSightVersion, &globals.OpsSightChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Helm Values with Secured Registry values
		currRegistries := make([]map[string]interface{}, 0)
		if _, ok := helmValuesMap["securedRegistries"]; ok {
			currRegistries = helmValuesMap["securedRegistries"].([]map[string]interface{})
		}
		newRegistry := map[string]interface{}{
			"url":      url,
			"user":     user,
			"password": pass,
		}
		newRegistries := append(currRegistries, newRegistry)
		util.SetHelmValueInMap(helmValuesMap, []string{"securedRegistries"}, newRegistries)

		// Update OpsSight Resources
		err = util.TemplateWithHelm3(opssightName, namespace, globals.OpsSightChartRepository, helmValuesMap)
		if err != nil {
			return fmt.Errorf("failed to update OpsSight resources due to %+v", err)
		}

		log.Infof("OpsSight has been successfully updated in namespace '%s'!", namespace)
		return nil
	},
}

// updateBDBACmd updates a BDBA instance
var updateBDBACmd = &cobra.Command{
	Use:           "bdba -n NAMESPACE",
	Example:       "synopsysctl update bdba -n <namespace>",
	Short:         "Update a BDBA instance",
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
		helmRelease, err := util.GetWithHelm3(globals.BDBAName, namespace, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get previous user defined values: %+v", err)
		}
		updateBDBACobraHelper.SetArgs(helmRelease.Config)

		// Get the flags to set Helm values
		helmValuesMap, err := updateBDBACobraHelper.GenerateHelmFlagsFromCobraFlags(cmd.Flags())
		if err != nil {
			return err
		}

		// Set the Version from the Release
		if cmd.Flags().Lookup("version").Changed {
			globals.BDBAVersion = cmd.Flags().Lookup("version").Value.String()
			util.SetHelmValueInMap(helmValuesMap, []string{"version"}, globals.BDBAVersion)
		} else {
			if versionFromRelease := util.GetValueFromRelease(helmRelease, []string{"version"}); versionFromRelease != nil {
				globals.BDBAVersion = versionFromRelease.(string)
			} else {
				return fmt.Errorf("please set --version for this update")
			}
		}

		// Update the Helm Chart Location
		err = UpdateHelmChartLocation(cmd.Flags(), globals.BDBAChartName, globals.BDBAVersion, &globals.BDBAChartRepository)
		if err != nil {
			return fmt.Errorf("failed to set the app resources location due to %+v", err)
		}

		// Update Resources
		err = util.UpdateWithHelm3(globals.BDBAName, namespace, globals.BDBAChartRepository, helmValuesMap, kubeConfigPath)
		if err != nil {
			return fmt.Errorf("failed to update BDBA resources due to %+v", err)
		}

		log.Infof("BDBA has been successfully Updated in namespace '%s'!", namespace)
		return nil
	},
}

func init() {
	// initialize global resource ctl structs for commands to use

	updateAlertCobraHelper = *alertctl.NewHelmValuesFromCobraFlags()
	updateOpsSightCobraHelper = *opssight.NewHelmValuesFromCobraFlags()
	updateBlackDuckCobraHelper = *blackduck.NewHelmValuesFromCobraFlags()
	updateBDBACobraHelper = *bdba.NewHelmValuesFromCobraFlags()

	rootCmd.AddCommand(updateCmd)

	// updateAlertCmd
	updateAlertCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(updateAlertCmd.PersistentFlags(), "namespace")
	updateAlertCobraHelper.AddCobraFlagsToCommand(updateAlertCmd, false)
	addChartLocationPathFlag(updateAlertCmd)
	updateCmd.AddCommand(updateAlertCmd)

	/* Update Black Duck Comamnds */

	// updateBlackDuckCmd
	updateBlackDuckCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(updateBlackDuckCmd.PersistentFlags(), "namespace")
	addChartLocationPathFlag(updateBlackDuckCmd)
	updateBlackDuckCmd.Flags().StringVar(&globals.DefaultBusyBoxImage, "busy-box-image", globals.DefaultBusyBoxImage, "Busy box image override for an air gapped customer (only use in case of updating security contexts)")
	updateBlackDuckCobraHelper.AddCobraFlagsToCommand(updateBlackDuckCmd, false)
	updateCmd.AddCommand(updateBlackDuckCmd)

	// updateBlackDuckMasterKeyCmd
	updateBlackDuckCmd.AddCommand(updateBlackDuckMasterKeyCmd)
	addChartLocationPathFlag(updateBlackDuckMasterKeyCmd)

	// updateBlackDuckMasterKeyNativeCmd
	updateBlackDuckMasterKeyCmd.AddCommand(updateBlackDuckMasterKeyNativeCmd)
	addChartLocationPathFlag(updateBlackDuckMasterKeyNativeCmd)

	// updateBlackDuckAddEnvironCmd
	updateBlackDuckCmd.AddCommand(updateBlackDuckAddEnvironCmd)
	addChartLocationPathFlag(updateBlackDuckAddEnvironCmd)

	/* Update OpsSight Comamnds */

	// updateOpsSightCmd
	updateOpsSightCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(updateOpsSightCmd.PersistentFlags(), "namespace")
	addChartLocationPathFlag(updateOpsSightCmd)
	updateOpsSightCobraHelper.AddCobraFlagsToCommand(updateOpsSightCmd, false)
	updateCmd.AddCommand(updateOpsSightCmd)

	// updateOpsSightExternalHostCmd
	updateOpsSightCmd.AddCommand(updateOpsSightExternalHostCmd)

	updateOpsSightExternalHostCmd.AddCommand(updateOpsSightExternalHostNativeCmd)

	// updateOpsSightAddRegistryCmd
	updateOpsSightCmd.AddCommand(updateOpsSightAddRegistryCmd)

	updateOpsSightAddRegistryCmd.AddCommand(updateOpsSightAddRegistryNativeCmd)

	// BDBA
	updateBDBACmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", namespace, "Namespace of the instance(s)")
	cobra.MarkFlagRequired(updateBDBACmd.PersistentFlags(), "namespace")
	updateBDBACobraHelper.AddCobraFlagsToCommand(updateBDBACmd, false)
	addChartLocationPathFlag(updateBDBACmd)
	updateCmd.AddCommand(updateBDBACmd)
}
