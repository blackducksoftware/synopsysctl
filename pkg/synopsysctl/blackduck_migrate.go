/*
 * Copyright (C) 2019 Synopsys, Inc.
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 *  under the License.
 */

package synopsysctl

import (
	"fmt"
	"strings"

	v1 "github.com/blackducksoftware/synopsysctl/pkg/api/blackduck/v1"
	"github.com/blackducksoftware/synopsysctl/pkg/blackduck"
	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	"github.com/imdario/mergo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// migrate migrates from synopsys operator to Helm based deployment
func migrate(bd *v1.Blackduck, operatorNamespace string, crdNamespace string, flags *pflag.FlagSet) error {
	// TODO ensure operator is installed and running a recent version that doesn't require additional migration

	log.Info("stopping Synopsys Operator")
	soOperatorDeploy, err := util.GetDeployment(kubeClient, operatorNamespace, "synopsys-operator")
	if err != nil {
		return err
	}

	soOperatorDeploy.Spec.Replicas = util.IntToInt32(0)
	soOperatorDeploy.Labels = util.InitLabels(soOperatorDeploy.Labels)
	soOperatorDeploy.Labels[fmt.Sprintf("synopsys.migrate.com/%s.%s", util.BlackDuckName, bd.Name)] = "true"

	_, err = util.UpdateDeployment(kubeClient, operatorNamespace, soOperatorDeploy)
	if err != nil {
		return err
	}

	// Generate Helm configuration
	helmValuesMap, err := blackDuckV1ToHelm(bd, operatorNamespace)
	if err != nil {
		return err
	}

	if util.IsOpenshift(kubeClient) {
		util.SetHelmValueInMap(helmValuesMap, []string{"isKubernetes"}, false)
	}

	helmValuesMapFromFlag, err := updateBlackDuckCobraHelper.GenerateHelmFlagsFromCobraFlags(flags)
	if err != nil {
		return err
	}

	if err := mergo.Merge(&helmValuesMap, helmValuesMapFromFlag, mergo.WithOverride); err != nil {
		return err
	}

	log.Info("deleting existing Black Duck resources")
	// TODO wait for resources to be deleted
	if err := deleteComponents(bd.Spec.Namespace, bd.Name, util.BlackDuckName); err != nil {
		return err
	}

	log.Info("upgrading Black Duck using Helm based deployment")

	// Update the Helm Chart Location
	bdVersion := helmValuesMap["imageTag"].(string)
	err = SetHelmChartLocation(flags, globals.BlackDuckChartName, bdVersion, &globals.BlackDuckChartRepository)
	if err != nil {
		return fmt.Errorf("failed to set the app resources location due to %+v", err)
	}

	var extraFiles []string
	size, found := helmValuesMap["size"]
	if found {
		extraFiles = append(extraFiles, fmt.Sprintf("%s.yaml", strings.ToLower(size.(string))))
	}

	secrets, err := blackduck.GetCertsFromFlagsAndSetHelmValue(bd.Name, namespace, flags, helmValuesMap)
	if err != nil {
		return err
	}

	for _, v := range secrets {
		if secret, err := util.GetSecret(kubeClient, namespace, v.Name); err == nil {
			secret.Data = v.Data
			secret.StringData = v.StringData
			if _, err := util.UpdateSecret(kubeClient, namespace, secret); err != nil {
				return fmt.Errorf("failed to update certificate secret: %+v", err)
			}
		} else {
			if _, err := kubeClient.CoreV1().Secrets(namespace).Create(&v); err != nil {
				return fmt.Errorf("failed to create certificate secret: %+v", err)
			}
		}
	}

	// if the services was exposed by the operator, we will not delete the service so that the IP
	// address remains the same. Thus we need to set this field to false so "Helm Create" does not try
	// to update the resource
	updateService := false
	if bd.Spec.ExposeService != util.NONE {
		if bd.Spec.ExposeService == strings.ToUpper(helmValuesMap["exposedServiceType"].(string)) {
			helmValuesMap["exposeui"] = false // synopsysctl will manage the exposed service
		} else {
			helmValuesMap["exposeui"] = true // helm chart needs to update the exposed service type
			updateService = true
		}
	}

	err = blackduck.CRUDServiceOrRoute(restconfig, kubeClient, bd.Spec.Namespace, bd.Name, helmValuesMap["exposeui"], helmValuesMap["exposedServiceType"], updateService)
	if err != nil {
		return err
	}

	err = util.CreateWithHelm3(bd.Name, bd.Spec.Namespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath, true, extraFiles...)
	if err != nil {
		return fmt.Errorf("failed to update File Ownerships in PVs: %+v", err)
	}
	util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Running")

	// Update Security Context Permissions
	// stop the black duck
	util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Stopped")
	err = runBlackDuckFileOwnershipJobs(bd.Name, bd.Spec.Namespace, bd.Spec.Version, helmValuesMap, flags)
	if err != nil {
		return fmt.Errorf("failed to update File Ownerships in PVs: %+v", err)
	}
	util.SetHelmValueInMap(helmValuesMap, []string{"status"}, "Running")

	// Deploy Resources
	err = util.CreateWithHelm3(bd.Name, bd.Spec.Namespace, globals.BlackDuckChartRepository, helmValuesMap, kubeConfigPath, false, extraFiles...)
	if err != nil {
		return fmt.Errorf("failed to create Blackduck resources: %+v", err)
	}

	log.Info("removing Black Duck custom resource")
	if err := util.DeleteBlackduck(blackDuckClient, bd.Name, bd.Namespace, &metav1.DeleteOptions{}); err != nil {
		return err
	}

	_, err = util.CheckAndUpdateNamespace(kubeClient, util.BlackDuckName, bd.Spec.Namespace, bd.Name, "", true)
	if err != nil {
		log.Warnf("unable to patch the namespace to remove app labels due to %+v", err)
	}

	// get the deployment, delete the migrate label and patch the deployment
	soOperatorDeploy, err = util.GetDeployment(kubeClient, operatorNamespace, "synopsys-operator")
	if err != nil {
		return err
	}
	soOperatorDeploy.Labels = util.InitLabels(soOperatorDeploy.Labels)
	delete(soOperatorDeploy.Labels, fmt.Sprintf("synopsys.migrate.com/%s.%s", util.BlackDuckName, bd.Name))
	soOperatorDeploy, err = util.UpdateDeployment(kubeClient, operatorNamespace, soOperatorDeploy)
	if err != nil {
		return err
	}

	skipDestroyorRestartOperator := false
	for key := range soOperatorDeploy.Labels {
		if strings.HasPrefix(key, "synopsys.migrate.com") {
			skipDestroyorRestartOperator = true
			break
		}
	}

	return destroyOperator(operatorNamespace, crdNamespace, skipDestroyorRestartOperator)
}

// popEnvironAndCompareValue check whether for the particular feature name in Black Duck environment variables, it is matching an expected value and also it removes its corresponding entry in environs
func popEnvironAndCompareValue(environs []string, featureName string, expectedValue string) (bool, []string) {
	for i, value := range environs {
		if strings.Contains(value, featureName) {
			environs = append(environs[:i], environs[i+1:]...)
			values := strings.SplitN(value, ":", 2)
			if len(values) == 2 {
				mapValue := strings.ToLower(strings.TrimSpace(values[1]))
				if strings.EqualFold(mapValue, expectedValue) {
					return true, environs
				}
			}
			return false, environs
		}
	}
	return false, environs
}

// blackDuckV1ToHelm converts Black Duck custom resources to helm flags
func blackDuckV1ToHelm(bd *v1.Blackduck, operatorNamespace string) (map[string]interface{}, error) {
	helmConfig := make(map[string]interface{})

	// Seal key
	if len(bd.Spec.SealKey) > 0 {
		decodedSealKey, err := util.Base64Decode(bd.Spec.SealKey)
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmConfig, []string{"sealKey"}, decodedSealKey)
	} else {
		// TODO handle ClusterScope
		sealSecret, err := kubeClient.CoreV1().Secrets(operatorNamespace).Get("blackduck-secret", metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		if _, ok := sealSecret.Data["SEAL_KEY"]; !ok {
			return nil, fmt.Errorf("couldn't find SEAL_KEY in %s/blackduck-secret", namespace)
		}
		util.SetHelmValueInMap(helmConfig, []string{"sealKey"}, string(sealSecret.Data["SEAL_KEY"]))
	}

	// Webserver
	webserverSecretName := util.GetResourceName(bd.Name, util.BlackDuckName, "webserver-certificate")
	var webserverSecret *corev1.Secret
	var err error
	if len(bd.Spec.Certificate) > 0 && len(bd.Spec.CertificateKey) > 0 {
		webserverSecret, err = blackduck.GetCertificateSecret(webserverSecretName, bd.Spec.Namespace, []byte(bd.Spec.Certificate), []byte(bd.Spec.CertificateKey))
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold(bd.Spec.CertificateName, "default") {
		currentSecret, err := kubeClient.CoreV1().Secrets(operatorNamespace).Get("blackduck-certificate", metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		webserverSecret, err = blackduck.GetCertificateSecret(webserverSecretName, bd.Spec.Namespace, currentSecret.Data["WEBSERVER_CUSTOM_CERT_FILE"], currentSecret.Data["WEBSERVER_CUSTOM_KEY_FILE"])
		if err != nil {
			return nil, err
		}
	} else {
		currentSecret, err := kubeClient.CoreV1().Secrets(bd.Spec.Namespace).Get(util.GetResourceName(bd.Name, util.BlackDuckName, "webserver-certificate"), metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		webserverSecret, err = blackduck.GetCertificateSecret(webserverSecretName, bd.Spec.Namespace, currentSecret.Data["WEBSERVER_CUSTOM_CERT_FILE"], currentSecret.Data["WEBSERVER_CUSTOM_KEY_FILE"])
		if err != nil {
			return nil, err
		}
	}
	if _, err := kubeClient.CoreV1().Secrets(bd.Spec.Namespace).Create(webserverSecret); err != nil && !k8serrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("failed to create secret: %+v", err)
	}
	util.SetHelmValueInMap(helmConfig, []string{"tlsCertSecretName"}, webserverSecretName)

	// Auth CA
	if len(bd.Spec.AuthCustomCA) > 0 {
		authSecretName := util.GetResourceName(bd.Name, util.BlackDuckName, "auth-custom-ca")
		authSecret, err := blackduck.GetAuthCertificateSecret(authSecretName, bd.Spec.Namespace, []byte(bd.Spec.AuthCustomCA))
		if err != nil {
			return nil, err
		}

		if _, err := kubeClient.CoreV1().Secrets(bd.Spec.Namespace).Create(authSecret); err != nil && !k8serrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("failed to create secret: %+v", err)
		}
		util.SetHelmValueInMap(helmConfig, []string{"certAuthCACertSecretName"}, authSecretName)
	}

	// Proxy Cert
	if len(bd.Spec.ProxyCertificate) > 0 {
		proxySecretName := util.GetResourceName(bd.Name, util.BlackDuckName, "proxy-certificate")
		proxySecret, err := blackduck.GetProxyCertificateSecret(proxySecretName, bd.Spec.Namespace, []byte(bd.Spec.ProxyCertificate))
		if err != nil {
			return nil, err
		}

		if _, err := kubeClient.CoreV1().Secrets(bd.Spec.Namespace).Create(proxySecret); err != nil && !k8serrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("failed to create secret: %+v", err)
		}
		util.SetHelmValueInMap(helmConfig, []string{"proxyCertSecretName"}, proxySecretName)
	}

	// Postgres
	if bd.Spec.ExternalPostgres != nil {
		adminPassword, err := util.Base64Decode(bd.Spec.ExternalPostgres.PostgresAdminPassword)
		if err != nil {
			return nil, err
		}
		userPassword, err := util.Base64Decode(bd.Spec.ExternalPostgres.PostgresUserPassword)
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "host"}, bd.Spec.ExternalPostgres.PostgresHost)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "port"}, bd.Spec.ExternalPostgres.PostgresPort)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "adminUserName"}, bd.Spec.ExternalPostgres.PostgresAdmin)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "userUserName"}, bd.Spec.ExternalPostgres.PostgresUser)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "ssl"}, bd.Spec.ExternalPostgres.PostgresUser)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "adminPassword"}, adminPassword)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "userPassword"}, userPassword)
	} else {
		adminPassword, err := util.Base64Decode(bd.Spec.AdminPassword)
		if err != nil {
			return nil, err
		}
		userPassword, err := util.Base64Decode(bd.Spec.UserPassword)
		if err != nil {
			return nil, err
		}

		if bd.Spec.PersistentStorage {
			util.SetHelmValueInMap(helmConfig, []string{"postgres", "adminUserName"}, "blackduck")
		} else {
			util.SetHelmValueInMap(helmConfig, []string{"postgres", "adminUserName"}, "postgres")
		}
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "userUserName"}, "blackduck_user")
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "adminPassword"}, adminPassword)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "userPassword"}, userPassword)
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "isExternal"}, false)
	}

	if len(bd.Spec.PVCStorageClass) > 0 {
		util.SetHelmValueInMap(helmConfig, []string{"storageClass"}, bd.Spec.PVCStorageClass)
	}
	util.SetHelmValueInMap(helmConfig, []string{"enablePersistentStorage"}, bd.Spec.PersistentStorage)
	util.SetHelmValueInMap(helmConfig, []string{"enableLivenessProbe"}, bd.Spec.LivenessProbes)

	if len(bd.Spec.DesiredState) > 0 {
		util.SetHelmValueInMap(helmConfig, []string{"status"}, bd.Spec.DesiredState)
	} else {
		util.SetHelmValueInMap(helmConfig, []string{"status"}, "Running")
	}

	if bd.Spec.RegistryConfiguration != nil {
		util.SetHelmValueInMap(helmConfig, []string{"registry"}, bd.Spec.RegistryConfiguration.Registry)
		util.SetHelmValueInMap(helmConfig, []string{"imagePullSecrets"}, bd.Spec.RegistryConfiguration.PullSecrets)
	}

	if len(bd.Spec.ImageRegistries) > 0 {
		blackduck.SetBlackDuckImageRegistriesInHelmValuesMap(helmConfig, bd.Spec.ImageRegistries)
	}

	var isSourceCodeUploadEnabled bool
	if isSourceCodeUploadEnabled, bd.Spec.Environs = popEnvironAndCompareValue(bd.Spec.Environs, "ENABLE_SOURCE_UPLOADS", "true"); isSourceCodeUploadEnabled {
		util.SetHelmValueInMap(helmConfig, []string{"enableSourceCodeUpload"}, true)
	}

	var isBDBAEnabled bool
	if isBDBAEnabled, bd.Spec.Environs = popEnvironAndCompareValue(bd.Spec.Environs, "USE_BINARY_UPLOADS", "1"); isBDBAEnabled {
		util.SetHelmValueInMap(helmConfig, []string{"enableBinaryScanner"}, true)
	}

	// NodeAffinities
	for k, v := range bd.Spec.NodeAffinities {
		util.SetHelmValueInMap(helmConfig, []string{k, "affinity"}, blackduck.OperatorAffinityToHelm(v))
	}

	//SecurityContexts
	securityContextIDNameToHelmPath := map[string][]string{
		"blackduck-postgres":       {"postgres", "podSecurityContext"},
		"blackduck-init":           {"init", "securityContext"},
		"blackduck-authentication": {"authentication", "podSecurityContext"},
		"blackduck-binnaryscanner": {"binaryscanner", "podSecurityContext"},
		"blackduck-cfssl":          {"cfssl", "podSecurityContext"},
		"blackduck-documentation":  {"documentation", "podSecurityContext"},
		"blackduck-jobrunner":      {"jobrunner", "podSecurityContext"},
		"blackduck-rabbitmq":       {"rabbitmq", "podSecurityContext"},
		"blackduck-registration":   {"registration", "podSecurityContext"},
		"blackduck-scan":           {"scan", "podSecurityContext"},
		"blackduck-uploadcache":    {"uploadcache", "podSecurityContext"},
		"blackduck-webapp":         {"webapp", "podSecurityContext"},
		"blackduck-logstash":       {"logstash", "securityContext"},
		"blackduck-nginx":          {"webserver", "podSecurityContext"},
		"appcheck-worker":          {"binaryscanner", "podSecurityContext"},
	}
	for k, v := range bd.Spec.SecurityContexts {
		pathToHelmValue := []string{k, "podSecurityContext"}                  // default path for new pods
		if newPathToHelmValue, ok := securityContextIDNameToHelmPath[k]; ok { // Override the security if it's present in the list
			pathToHelmValue = newPathToHelmValue
		}

		util.SetHelmValueInMap(helmConfig, pathToHelmValue, blackduck.OperatorAPISecurityContextToHelm(v))
	}

	// Environs
	for _, v := range bd.Spec.Environs {
		values := strings.SplitN(v, ":", 2)
		if len(values) == 2 {
			util.SetHelmValueInMap(helmConfig, []string{"environs", values[0]}, values[1])
		}
	}

	// Map existing PVCs
	if bd.Spec.PersistentStorage {
		util.SetHelmValueInMap(helmConfig, []string{"postgres", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-postgres", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"authentication", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-authentication", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"cfssl", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-cfssl", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"logstash", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-logstash", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"registration", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-registration", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"uploadcache", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-uploadcache-data", bd.Name))
		util.SetHelmValueInMap(helmConfig, []string{"webapp", "persistentVolumeClaimName"}, fmt.Sprintf("%s-blackduck-webapp", bd.Name))
	}

	util.SetHelmValueInMap(helmConfig, []string{"size"}, strings.ToLower(bd.Spec.Size))

	// expose service
	util.SetHelmValueInMap(helmConfig, []string{"exposeui"}, false)
	switch bd.Spec.ExposeService {
	case util.NODEPORT:
		util.SetHelmValueInMap(helmConfig, []string{"exposedServiceType"}, "NodePort")
	case util.LOADBALANCER:
		util.SetHelmValueInMap(helmConfig, []string{"exposedServiceType"}, "LoadBalancer")
	case util.OPENSHIFT:
		util.SetHelmValueInMap(helmConfig, []string{"exposedServiceType"}, "OpenShift")
	}

	return helmConfig, nil
}

// deleteComponents delete all the resources based on name and application type
func deleteComponents(namespace string, name string, app string) error {
	labelSelector := fmt.Sprintf("app=%s, name=%s", app, name)
	deploy, err := util.ListDeployments(kubeClient, namespace, labelSelector)
	if err != nil {
		return err
	}
	for _, v := range deploy.Items {
		if err := util.DeleteDeployment(kubeClient, namespace, v.Name); err != nil {
			return err
		}
	}

	rc, err := util.ListReplicationControllers(kubeClient, namespace, labelSelector)
	if err != nil {
		return err
	}
	for _, v := range rc.Items {
		if err := util.DeleteReplicationController(kubeClient, namespace, v.Name); err != nil {
			return err
		}
	}

	svc, err := util.ListServices(kubeClient, namespace, labelSelector)
	if err != nil {
		return err
	}
	for _, v := range svc.Items {
		if !strings.Contains(v.Name, "-exposed") {
			if err := util.DeleteService(kubeClient, namespace, v.Name); err != nil {
				return err
			}
		}
	}

	cm, err := util.ListConfigMaps(kubeClient, namespace, labelSelector)
	if err != nil {
		return err
	}
	for _, v := range cm.Items {
		if err := util.DeleteConfigMap(kubeClient, namespace, v.Name); err != nil {
			return err
		}
	}

	secret, err := util.ListSecrets(kubeClient, namespace, fmt.Sprintf("%s, component!=secret", labelSelector))
	if err != nil {
		return err
	}
	for _, v := range secret.Items {
		if err := util.DeleteSecret(kubeClient, namespace, v.Name); err != nil {
			return err
		}
	}

	serviceAccounts, err := util.ListServiceAccounts(kubeClient, namespace, labelSelector)
	if err != nil {
		return err
	}
	for _, v := range serviceAccounts.Items {
		if err := util.DeleteServiceAccount(kubeClient, namespace, v.Name); err != nil {
			return err
		}
	}

	return nil
}
