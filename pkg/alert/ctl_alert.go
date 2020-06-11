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

package alert

import (
	"encoding/json"
	"fmt"
	"strings"

	blackduckv1 "github.com/blackducksoftware/synopsysctl/pkg/api/blackduck/v1"
	"github.com/blackducksoftware/synopsysctl/pkg/blackduck"
	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
)

// HelmValuesFromCobraFlags is a type for converting synopsysctl flags
// to Helm Chart fields and values
// args: map of helm chart field to value
type HelmValuesFromCobraFlags struct {
	args     map[string]interface{}
	flagTree FlagTree
}

// FlagTree is a set of fields needed to configure the Polaris Reporting Helm Chart
type FlagTree struct {
	Version                     string
	DeploymentResourcesFilePath string
	Registry                    string
	PullSecrets                 []string
	StandAlone                  string
	ExposeService               string
	EncryptionPassword          string
	EncryptionGlobalSalt        string
	CertificateFilePath         string
	CertificateKeyFilePath      string
	JavaKeyStoreFilePath        string
	Environs                    []string
	PersistentStorage           string
	PVCStorageClass             string
	PVCFilePath                 string
	SecurityContextFilePath     string
	Port                        int32
}

// DefaultFlagTree ...
// [Dev Note]: These should match the Helm Chart's Values.yaml
var DefaultFlagTree = FlagTree{
	Version:           globals.AlertVersion,
	Registry:          "docker.io/blackducksoftware",
	StandAlone:        "true",
	ExposeService:     util.NODEPORT,
	PersistentStorage: "true",
	Port:              8443,
}

// NewHelmValuesFromCobraFlags returns an initialized HelmValuesFromCobraFlags
func NewHelmValuesFromCobraFlags() *HelmValuesFromCobraFlags {
	return &HelmValuesFromCobraFlags{
		args:     make(map[string]interface{}, 0),
		flagTree: FlagTree{},
	}
}

// GetArgs returns the map of helm chart fields to values
func (ctl *HelmValuesFromCobraFlags) GetArgs() map[string]interface{} {
	return ctl.args
}

// SetArgs set the map to values
func (ctl *HelmValuesFromCobraFlags) SetArgs(args map[string]interface{}) {
	for key, value := range args {
		ctl.args[key] = value
	}
}

// AddCobraFlagsToCommand adds flags for the Polaris-Reporting helm chart to the cmd
// master=true is used to add all flags for creating an instance
// master=false is used to add a subset of flags for updating an instance
func (ctl *HelmValuesFromCobraFlags) AddCobraFlagsToCommand(cmd *cobra.Command, master bool) {
	// [DEV NOTE:] please organize flags in order of importance
	cmd.Flags().SortFlags = false

	// Application Version and Image Tag
	cmd.Flags().StringVar(&ctl.flagTree.Version, "version", DefaultFlagTree.Version, "Version of Alert\n")
	if master {
		cobra.MarkFlagRequired(cmd.Flags(), "version")
	}

	// Storage
	cmd.Flags().StringVar(&ctl.flagTree.DeploymentResourcesFilePath, "deployment-resources-file-path", ctl.flagTree.DeploymentResourcesFilePath, "Absolute path to a file containing a list of deployment Resources json structs")
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.PVCStorageClass, "pvc-storage-class", ctl.flagTree.PVCStorageClass, "Storage class for the persistent volume claim")
		cmd.Flags().StringVar(&ctl.flagTree.PersistentStorage, "persistent-storage", "true", "If true, Alert has persistent storage [true|false]")
	}
	cmd.Flags().StringVar(&ctl.flagTree.PVCFilePath, "pvc-file-path", ctl.flagTree.PVCFilePath, "Absolute path to a file containing a list of PVC json structs\n")

	// Pulling images values
	cmd.Flags().StringVar(&ctl.flagTree.Registry, "registry", DefaultFlagTree.Registry, "Name of the registry to use for images")
	cmd.Flags().StringSliceVar(&ctl.flagTree.PullSecrets, "pull-secret-name", ctl.flagTree.PullSecrets, "Only if the registry requires authentication\n")

	// Standalone (uses it's own cfssl)
	cmd.Flags().StringVar(&ctl.flagTree.StandAlone, "standalone", DefaultFlagTree.StandAlone, "If true, Alert runs in standalone mode [true|false]\n")

	// Exposing the UI
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.ExposeService, "expose-ui", DefaultFlagTree.ExposeService, "Service type to expose Alert's user interface [NODEPORT|LOADBALANCER|OPENSHIFT|NONE]\n")
	} else {
		cmd.Flags().StringVar(&ctl.flagTree.ExposeService, "expose-ui", ctl.flagTree.ExposeService, "Service type to expose Alert's user interface [NODEPORT|LOADBALANCER|OPENSHIFT|NONE]\n")
	}

	// Secrets Values
	cmd.Flags().StringVar(&ctl.flagTree.EncryptionPassword, "encryption-password", ctl.flagTree.EncryptionPassword, "Encryption Password for Alert")
	cmd.Flags().StringVar(&ctl.flagTree.EncryptionGlobalSalt, "encryption-global-salt", ctl.flagTree.EncryptionGlobalSalt, "Encryption Global Salt for Alert")
	cmd.Flags().StringVar(&ctl.flagTree.CertificateFilePath, "certificate-file-path", ctl.flagTree.CertificateFilePath, "Absolute path to the PEM certificate to use for Alert")
	cmd.Flags().StringVar(&ctl.flagTree.CertificateKeyFilePath, "certificate-key-file-path", ctl.flagTree.CertificateKeyFilePath, "Absolute path to the PEM certificate key for Alert")
	cmd.Flags().StringVar(&ctl.flagTree.JavaKeyStoreFilePath, "java-keystore-file-path", ctl.flagTree.JavaKeyStoreFilePath, "Absolute path to the Java Keystore to use for Alert\n")

	// Environs
	cmd.Flags().StringSliceVar(&ctl.flagTree.Environs, "environs", ctl.flagTree.Environs, "Environment variables of Alert\n")

	// Security Contexts
	cmd.Flags().StringVar(&ctl.flagTree.SecurityContextFilePath, "security-context-file-path", ctl.flagTree.SecurityContextFilePath, "Absolute path to a file containing a map of pod names to security contexts runAsUser, fsGroup, and runAsGroup\n")

	// Port
	cmd.Flags().Int32Var(&ctl.flagTree.Port, "port", DefaultFlagTree.Port, "Port of Alert") // only for devs
	cmd.Flags().MarkHidden("port")
}

// CheckValuesFromFlags returns an error if a value stored in the struct will not be able to be
// used in the AlertSpec
func (ctl *HelmValuesFromCobraFlags) CheckValuesFromFlags(flagset *pflag.FlagSet) error {
	if FlagWasSet(flagset, "encryption-password") {
		encryptPassLength := len(ctl.flagTree.EncryptionPassword)
		if encryptPassLength > 0 && encryptPassLength < 16 {
			return fmt.Errorf("flag EncryptionPassword is %d characters. Must be 16 or more characters", encryptPassLength)
		}
	}
	if FlagWasSet(flagset, "encryption-global-salt") {
		globalSaltLength := len(ctl.flagTree.EncryptionGlobalSalt)
		if globalSaltLength > 0 && globalSaltLength < 16 {
			return fmt.Errorf("flag EncryptionGlobalSalt is %d characters. Must be 16 or more characters", globalSaltLength)
		}
	}
	if FlagWasSet(flagset, "expose-ui") {
		isValid := util.IsExposeServiceValid(ctl.flagTree.ExposeService)
		if !isValid {
			return fmt.Errorf("expose ui must be '%s', '%s', '%s' or '%s'", util.NODEPORT, util.LOADBALANCER, util.OPENSHIFT, util.NONE)
		}
	}
	if (FlagWasSet(flagset, "certificate-file-path") || FlagWasSet(flagset, "certificate-key-file-path")) && !(FlagWasSet(flagset, "certificate-file-path") && FlagWasSet(flagset, "certificate-key-file-path")) {
		return fmt.Errorf("must set both certificate-file-path and certificate-key-file-path")
	}
	return nil
}

// FlagWasSet returns true if a flag was changed and it exists, otherwise it returns false
func FlagWasSet(flagset *pflag.FlagSet, flagName string) bool {
	if flagset.Lookup(flagName) != nil && flagset.Lookup(flagName).Changed {
		return true
	}
	return false
}

// GenerateHelmFlagsFromCobraFlags checks each flag in synopsysctl and updates the map to
// contain the corresponding helm chart field and value
func (ctl *HelmValuesFromCobraFlags) GenerateHelmFlagsFromCobraFlags(flagset *pflag.FlagSet) (map[string]interface{}, error) {
	err := ctl.CheckValuesFromFlags(flagset)
	if err != nil {
		return nil, err
	}

	flagset.VisitAll(ctl.AddHelmValueByCobraFlag)

	return ctl.args, nil
}

// AddHelmValueByCobraFlag adds the helm chart field and value based on the flag set
// in synopsysctl
func (ctl *HelmValuesFromCobraFlags) AddHelmValueByCobraFlag(f *pflag.Flag) {
	if f.Changed {
		log.Debugf("flag '%s': CHANGED", f.Name)
		switch f.Name {
		case "version":
			util.SetHelmValueInMap(ctl.args, []string{"alert", "imageTag"}, ctl.flagTree.Version)
		case "standalone":
			standAloneVal := strings.ToUpper(ctl.flagTree.StandAlone) == "TRUE"
			util.SetHelmValueInMap(ctl.args, []string{"enableStandalone"}, standAloneVal)
		case "deployment-resources-file-path":
			util.GetDeploymentResources(ctl.flagTree.DeploymentResourcesFilePath, ctl.args, "heapMaxMemory")
		case "expose-ui":
			util.SetHelmValueInMap(ctl.args, []string{"exposeui"}, true)
			switch ctl.flagTree.ExposeService {
			case util.NODEPORT:
				util.SetHelmValueInMap(ctl.args, []string{"exposedServiceType"}, "NodePort")
			case util.LOADBALANCER:
				util.SetHelmValueInMap(ctl.args, []string{"exposedServiceType"}, "LoadBalancer")
			case util.OPENSHIFT:
				util.SetHelmValueInMap(ctl.args, []string{"exposedServiceType"}, "OpenShift")
			default:
				util.SetHelmValueInMap(ctl.args, []string{"exposeui"}, false)
			}
		case "port":
			util.SetHelmValueInMap(ctl.args, []string{"alert", "port"}, ctl.flagTree.Port)
		case "encryption-password":
			util.SetHelmValueInMap(ctl.args, []string{"setEncryptionSecretData"}, true)
			util.SetHelmValueInMap(ctl.args, []string{"alertEncryptionPassword"}, ctl.flagTree.EncryptionPassword)
		case "encryption-global-salt":
			util.SetHelmValueInMap(ctl.args, []string{"setEncryptionSecretData"}, true)
			util.SetHelmValueInMap(ctl.args, []string{"alertEncryptionGlobalSalt"}, ctl.flagTree.EncryptionGlobalSalt)
		case "pvc-file-path":
			data, err := util.ReadFileData(ctl.flagTree.PVCFilePath)
			if err != nil {
				log.Fatalf("failed to read pvc file: %+v", err)
			}
			pvcs := []blackduckv1.PVC{}
			err = json.Unmarshal([]byte(data), &pvcs)
			if err != nil {
				log.Fatalf("failed to unmarshal pvc structs: %+v", err)
			}
			// Add values here if the path in Values.yaml is different than just the pvcIDName
			// ex: the pvcIDName as "alert" but the path is alert.something.claimSize
			// ex: the pvcIDName is "alert-container" but the path is alert.claimSize
			pvcIDNameToHelmPath := map[string][]string{
				// "alert": {"alert"},
				// "postgres": []string{"postgres"},
			}
			for _, pvc := range pvcs {
				pvcIDName := pvc.Name
				pathToHelmValue := []string{pvcIDName}                            // default path is the pvcIDName
				if newPathToHelmValue, ok := pvcIDNameToHelmPath[pvcIDName]; ok { // Override the path if it isn't the pvcIDName
					pathToHelmValue = newPathToHelmValue
				}
				// Support custom PVC (different than the PVC provided in the Helm Chart)
				util.SetHelmValueInMap(ctl.args, append(pathToHelmValue, "persistentVolumeClaimName"), pvc.PVCName)
				// Set values for PVC provided in the Helm Chart
				util.SetHelmValueInMap(ctl.args, append(pathToHelmValue, "claimSize"), pvc.Size)
				util.SetHelmValueInMap(ctl.args, append(pathToHelmValue, "storageClass"), pvc.StorageClass)
				util.SetHelmValueInMap(ctl.args, append(pathToHelmValue, "volumeName"), pvc.VolumeName)
			}
		case "persistent-storage":
			persistentStorageVal := strings.ToUpper(ctl.flagTree.PersistentStorage) == "TRUE"
			util.SetHelmValueInMap(ctl.args, []string{"enablePersistentStorage"}, persistentStorageVal)
		case "pvc-storage-class":
			util.SetHelmValueInMap(ctl.args, []string{"storageClass"}, ctl.flagTree.PVCStorageClass)
		case "environs":
			// TODO: Make sure this is converted correclty
			envMap := map[string]interface{}{}
			for _, env := range ctl.flagTree.Environs {
				envSplit := strings.SplitN(env, ":", 2)
				envMap[envSplit[0]] = envSplit[1]
			}
			util.SetHelmValueInMap(ctl.args, []string{"environs"}, envMap)
		case "registry":
			util.SetHelmValueInMap(ctl.args, []string{"registry"}, ctl.flagTree.Registry)
		case "pull-secret-name":
			util.SetHelmValueInMap(ctl.args, []string{"imagePullSecrets"}, ctl.flagTree.PullSecrets)
		case "security-context-file-path":
			data, err := util.ReadFileData(ctl.flagTree.SecurityContextFilePath)
			if err != nil {
				log.Errorf("failed to read security context file: %+v", err)
				return
			}
			securityContexts := map[string]corev1.PodSecurityContext{}
			err = json.Unmarshal([]byte(data), &securityContexts)
			if err != nil {
				log.Errorf("failed to unmarshal security contexts: %+v", err)
				return
			}
			for k, v := range securityContexts {
				util.SetHelmValueInMap(ctl.args, []string{k, "podSecurityContext"}, blackduck.CorePodSecurityContextToHelm(v))
			}
		default:
			log.Debugf("flag '%s': NOT FOUND", f.Name)
		}
	} else {
		log.Debugf("flag '%s': UNCHANGED", f.Name)
	}
}
