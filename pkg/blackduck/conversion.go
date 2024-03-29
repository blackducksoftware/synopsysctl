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

package blackduck

import (
	"io/ioutil"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/api"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
)

// OperatorAffinityToHelm ...
func OperatorAffinityToHelm(opAffinity []api.NodeAffinity) map[string]interface{} {
	hardTerms := make([]map[string]interface{}, 0)
	softTerms := make([]map[string]interface{}, 0)
	for _, aValue := range opAffinity {
		// Create Helm Values for each nodeSelectorTerm
		nodeSelectorRequirements := []map[string]interface{}{
			{
				"key":      aValue.Key,
				"operator": corev1.NodeSelectorOperator(aValue.Op),
				"values":   aValue.Values,
			},
		}
		nodeSelectorTerm := map[string]interface{}{
			"matchExpressions": nodeSelectorRequirements,
		}

		// Divide each nodeSelectorTerm into hard and soft lists
		if strings.EqualFold(aValue.AffinityType, "hard") {
			hardTerms = append(hardTerms, nodeSelectorTerm)
		} else if strings.EqualFold(aValue.AffinityType, "soft") {
			softTerms = append(softTerms, nodeSelectorTerm)
		}
	}

	affinity := make(map[string]interface{}, 0)
	if len(hardTerms) > 0 || len(softTerms) > 0 {
		if len(hardTerms) > 0 {
			nodeSelector := map[string]interface{}{
				"nodeSelectorTerms": hardTerms,
			}
			util.SetHelmValueInMap(affinity, []string{"nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution"}, nodeSelector)
		}
		if len(softTerms) > 0 {
			for _, s := range softTerms {
				preferredSchedulingTerm := map[string]interface{}{
					"weight":     100,
					"preference": s,
				}
				currPrefferedNodeAffinities := util.GetHelmValueFromMap(affinity, []string{"nodeAffinity", "preferredDuringSchedulingIgnoredDuringExecution"})
				if currPrefferedNodeAffinities != nil {
					listPrefferredNodeAffinities := currPrefferedNodeAffinities.([]map[string]interface{})
					updatedPrefferedNodeAfinities := append(listPrefferredNodeAffinities, preferredSchedulingTerm)
					util.SetHelmValueInMap(affinity, []string{"nodeAffinity", "preferredDuringSchedulingIgnoredDuringExecution"}, updatedPrefferedNodeAfinities)
				} else {
					util.SetHelmValueInMap(affinity, []string{"nodeAffinity", "preferredDuringSchedulingIgnoredDuringExecution"}, []map[string]interface{}{preferredSchedulingTerm})
				}

			}
		}
	}

	return affinity
}

// CorePodSecurityContextToHelm converts pod security context format for Helm Values
// NOTE: SecurityContext doens't have fsGroup (PodSecurityContext has fsGroup)
func CorePodSecurityContextToHelm(psc corev1.PodSecurityContext) map[string]interface{} {
	helmSecurityContexts := make(map[string]interface{}, 0)
	if psc.SELinuxOptions != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"seLinuxOptions"}, *psc.SELinuxOptions)
	}
	if psc.WindowsOptions != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"windowsOptions"}, *psc.WindowsOptions)
	}
	if psc.RunAsUser != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"runAsUser"}, *psc.RunAsUser)
	}
	if psc.RunAsGroup != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"runAsGroup"}, *psc.RunAsGroup)
	}
	if psc.RunAsNonRoot != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"runAsNonRoot"}, *psc.RunAsNonRoot)
	}
	if psc.SupplementalGroups != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"supplementalGroups"}, psc.SupplementalGroups)
	}
	if psc.FSGroup != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"fsGroup"}, *psc.FSGroup)
	}
	if psc.Sysctls != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"sysctls"}, psc.Sysctls)
	}
	return helmSecurityContexts
}

// OperatorAPISecurityContextToHelm converts security context format for Helm Values
// NOTE: SecurityContext doens't have fsGroup (PodSecurityContext has fsGroup)
func OperatorAPISecurityContextToHelm(opSecurityContext api.SecurityContext) map[string]interface{} {
	helmSecurityContexts := make(map[string]interface{}, 0)
	if opSecurityContext.FsGroup != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"fsGroup"}, *opSecurityContext.FsGroup)
	}
	if opSecurityContext.RunAsUser != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"runAsUser"}, *opSecurityContext.RunAsUser)
	}
	if opSecurityContext.RunAsGroup != nil {
		util.SetHelmValueInMap(helmSecurityContexts, []string{"runAsGroup"}, *opSecurityContext.RunAsGroup)
	}
	return helmSecurityContexts
}

// GetCertsFromFlagsAndSetHelmValue converts synopsysctl certificate files to kube secrets
func GetCertsFromFlagsAndSetHelmValue(name string, namespace string, flagset *pflag.FlagSet, helmVal map[string]interface{}) ([]corev1.Secret, error) {
	var objects []corev1.Secret
	if flagset.Lookup("certificate-file-path").Changed && flagset.Lookup("certificate-key-file-path").Changed {
		certPath := flagset.Lookup("certificate-file-path").Value.String()
		keyPath := flagset.Lookup("certificate-key-file-path").Value.String()
		secretName := util.GetResourceName(name, util.BlackDuckName, "webserver-certificate")

		secret, err := GetCertificateSecretFromFile(secretName, namespace, certPath, keyPath)
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmVal, []string{"tlsCertSecretName"}, secretName)
		objects = append(objects, *secret)
	}

	if flagset.Lookup("proxy-certificate-file-path").Changed {
		certPath := flagset.Lookup("proxy-certificate-file-path").Value.String()
		secretName := util.GetResourceName(name, util.BlackDuckName, "proxy-certificate")

		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		secret, err := GetSecret(secretName, namespace, cert, "HUB_PROXY_CERT_FILE")
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmVal, []string{"proxyCertSecretName"}, secretName)
		objects = append(objects, *secret)
	}

	if flagset.Lookup("auth-custom-ca-file-path").Changed {
		certPath := flagset.Lookup("auth-custom-ca-file-path").Value.String()
		secretName := util.GetResourceName(name, util.BlackDuckName, "auth-custom-ca")

		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		secret, err := GetSecret(secretName, namespace, cert, "AUTH_CUSTOM_CA")
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmVal, []string{"certAuthCACertSecretName"}, secretName)
		objects = append(objects, *secret)
	}

	if flagset.Lookup("proxy-password-file-path").Changed {
		certPath := flagset.Lookup("proxy-password-file-path").Value.String()
		secretName := util.GetResourceName(name, util.BlackDuckName, "proxy-password")

		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		secret, err := GetSecret(secretName, namespace, cert, "HUB_PROXY_PASSWORD_FILE")
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmVal, []string{"proxyPasswordSecretName"}, secretName)
		objects = append(objects, *secret)
	}

	if flagset.Lookup("ldap-password-file-path").Changed {
		certPath := flagset.Lookup("ldap-password-file-path").Value.String()
		secretName := util.GetResourceName(name, util.BlackDuckName, "ldap-password")

		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		secret, err := GetSecret(secretName, namespace, cert, "LDAP_TRUST_STORE_PASSWORD_FILE")
		if err != nil {
			return nil, err
		}
		util.SetHelmValueInMap(helmVal, []string{"ldapPasswordSecretName"}, secretName)
		objects = append(objects, *secret)
	}

	return objects, nil
}
