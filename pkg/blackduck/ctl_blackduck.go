/*
Copyright (C) 2018 Synopsys, Inc.

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
	"encoding/json"
	"fmt"
	"strings"

	blackduckv1 "github.com/blackducksoftware/synopsysctl/pkg/api/blackduck/v1"
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

// FlagTree is a set of fields needed to configure the Blackduck Helm Chart
type FlagTree struct {
	Version string

	Registry        string
	PullSecrets     []string
	ImageRegistries []string

	PvcStorageClass             string
	PersistentStorage           string
	PVCFilePath                 string
	Size                        string
	DeploymentResourcesFilePath string

	ExposeService   string
	ExposedNodePort string

	ExternalPostgresHost          string
	ExternalPostgresPort          int
	ExternalPostgresAdmin         string
	ExternalPostgresUser          string
	ExternalPostgresSsl           string
	ExternalPostgresAdminPassword string
	ExternalPostgresUserPassword  string
	PostgresClaimSize             string
	AdminPassword                 string
	UserPassword                  string

	CertificateName          string
	CertificateFilePath      string
	CertificateKeyFilePath   string
	ProxyCertificateFilePath string
	AuthCustomCAFilePath     string

	SealKey string

	Environs []string

	LivenessProbes         string
	EnableBinaryAnalysis   bool
	EnableSourceCodeUpload bool
	EnableInitContainer    string

	NodeAffinityFilePath    string
	SecurityContextFilePath string
}

// DefaultFlagTree ...
// [Dev Note]: These should match the Helm Chart's Values.yaml
var DefaultFlagTree = FlagTree{
	// Version
	Version: globals.BlackDuckVersion,
	//Registry Config
	Registry: "docker.io/blackducksoftware",
	// Storage
	PersistentStorage: "true",
	Size:              "small",
	// Expose UI
	ExposeService: util.NONE,
	// Postgres
	ExternalPostgresPort: 5432,
	ExternalPostgresUser: "blackduck_user",
	ExternalPostgresSsl:  "true",
	PostgresClaimSize:    "150Gi",
	// Certificates
	// Seal Key
	// Environs
	// Enable Features
	EnableBinaryAnalysis:   false,
	EnableSourceCodeUpload: false,
	// Enable init containers to verify the Postgres database is initialized
	EnableInitContainer: "true",
	// Extra Config Settings
}

// GetDefaultFlagTree ...
func GetDefaultFlagTree() *FlagTree {
	return &DefaultFlagTree
}

// NewHelmValuesFromCobraFlags creates a new HelmValuesFromCobraFlags type
func NewHelmValuesFromCobraFlags() *HelmValuesFromCobraFlags {
	return &HelmValuesFromCobraFlags{
		args: make(map[string]interface{}, 0),
	}
}

// SetArgs set the map to values
func (ctl *HelmValuesFromCobraFlags) SetArgs(args map[string]interface{}) {
	for key, value := range args {
		ctl.args[key] = value
	}
}

// GetArgs returns the map of helm chart fields to values
func (ctl *HelmValuesFromCobraFlags) GetArgs() map[string]interface{} {
	return ctl.args
}

// AddCobraFlagsToCommand adds flags to a Cobra Command that are need for BlackDuck's Spec.
// The flags map to fields in the CRSpecBuilderFromCobraFlags struct.
func (ctl *HelmValuesFromCobraFlags) AddCobraFlagsToCommand(cmd *cobra.Command, isCreateCmd bool) {
	// [DEV NOTE:] please organize flags in order of importance
	cmd.Flags().SortFlags = false

	defaults := &FlagTree{}
	if isCreateCmd {
		defaults = GetDefaultFlagTree()
	}

	// Version
	cmd.Flags().StringVar(&ctl.flagTree.Version, "version", defaults.Version, "Version of Black Duck")

	// Registry Config
	cmd.Flags().StringVar(&ctl.flagTree.Registry, "registry", defaults.Registry, "Name of the registry to use for images e.g. docker.io/blackducksoftware")
	cmd.Flags().StringSliceVar(&ctl.flagTree.PullSecrets, "pull-secret-name", defaults.PullSecrets, "Only if the registry requires authentication\n")
	cmd.Flags().StringSliceVar(&ctl.flagTree.ImageRegistries, "image-registries", defaults.ImageRegistries, "Set the image registry for each image")
	cmd.Flags().MarkHidden("image-registries") // only for devs

	// Storage
	if isCreateCmd {
		cmd.Flags().StringVar(&ctl.flagTree.PvcStorageClass, "pvc-storage-class", defaults.PvcStorageClass, "Name of Storage Class for the PVC")
		cmd.Flags().StringVar(&ctl.flagTree.PersistentStorage, "persistent-storage", defaults.PersistentStorage, "If true, Black Duck has persistent storage [true|false]")
		cmd.Flags().StringVar(&ctl.flagTree.PVCFilePath, "pvc-file-path", defaults.PVCFilePath, "Absolute path to a file containing a list of PVC json structs")
	}
	cmd.Flags().StringVar(&ctl.flagTree.Size, "size", defaults.Size, "Size of Black Duck [small|medium|large|x-large]")
	cmd.Flags().StringVar(&ctl.flagTree.DeploymentResourcesFilePath, "deployment-resources-file-path", defaults.DeploymentResourcesFilePath, "Absolute path to a file containing a list of deployment Resources json structs\n")

	// Expose UI
	cmd.Flags().StringVar(&ctl.flagTree.ExposeService, "expose-ui", defaults.ExposeService, "Service type of Black Duck webserver's user interface [NODEPORT|LOADBALANCER|OPENSHIFT|NONE]\n")
	cmd.Flags().StringVar(&ctl.flagTree.ExposedNodePort, "node-port", defaults.ExposedNodePort, "Value for the NodePort's port (default random)\n")

	// Postgres
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresHost, "external-postgres-host", defaults.ExternalPostgresHost, "Host of external Postgres")
	cmd.Flags().IntVar(&ctl.flagTree.ExternalPostgresPort, "external-postgres-port", defaults.ExternalPostgresPort, "Port of external Postgres")
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresAdmin, "external-postgres-admin", defaults.ExternalPostgresAdmin, "Name of 'admin' of external Postgres database")
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresUser, "external-postgres-user", defaults.ExternalPostgresUser, "Name of 'user' of external Postgres database")
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresSsl, "external-postgres-ssl", defaults.ExternalPostgresSsl, "If true, Black Duck uses SSL for external Postgres connection [true|false]")
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresAdminPassword, "external-postgres-admin-password", defaults.ExternalPostgresAdminPassword, "'admin' password of external Postgres database")
	cmd.Flags().StringVar(&ctl.flagTree.ExternalPostgresUserPassword, "external-postgres-user-password", defaults.ExternalPostgresUserPassword, "'user' password of external Postgres database")
	cmd.Flags().StringVar(&ctl.flagTree.PostgresClaimSize, "postgres-claim-size", defaults.PostgresClaimSize, "Size of the blackduck-postgres PVC")
	cmd.Flags().StringVar(&ctl.flagTree.AdminPassword, "admin-password", defaults.AdminPassword, "'admin' password of Postgres database")
	cmd.Flags().StringVar(&ctl.flagTree.UserPassword, "user-password", defaults.UserPassword, "'user' password of Postgres database\n")

	// Certificates
	cmd.Flags().StringVar(&ctl.flagTree.CertificateName, "certificate-name", defaults.CertificateName, "Name of Black Duck nginx certificate")
	cmd.Flags().StringVar(&ctl.flagTree.CertificateFilePath, "certificate-file-path", defaults.CertificateFilePath, "Absolute path to a file for the Black Duck nginx certificate")
	cmd.Flags().StringVar(&ctl.flagTree.CertificateKeyFilePath, "certificate-key-file-path", defaults.CertificateKeyFilePath, "Absolute path to a file for the Black Duck nginx certificate key")
	cmd.Flags().StringVar(&ctl.flagTree.ProxyCertificateFilePath, "proxy-certificate-file-path", defaults.ProxyCertificateFilePath, "Absolute path to a file for the Black Duck proxy server’s Certificate Authority (CA)")
	cmd.Flags().StringVar(&ctl.flagTree.AuthCustomCAFilePath, "auth-custom-ca-file-path", defaults.AuthCustomCAFilePath, "Absolute path to a file for the Custom Auth CA for Black Duck\n")

	// Seal Key
	if isCreateCmd {
		cmd.Flags().StringVar(&ctl.flagTree.SealKey, "seal-key", defaults.SealKey, "Seal key to encrypt the master key when Source code upload is enabled and it should be of length 32\n")
	}

	// Environs
	cmd.Flags().StringSliceVar(&ctl.flagTree.Environs, "environs", defaults.Environs, "List of environment variables\n")

	// Enable Features
	cmd.Flags().StringVar(&ctl.flagTree.LivenessProbes, "liveness-probes", defaults.LivenessProbes, "If true, Black Duck uses liveness probes [true|false]")
	cmd.Flags().BoolVar(&ctl.flagTree.EnableBinaryAnalysis, "enable-binary-analysis", defaults.EnableBinaryAnalysis, "If true, enable binary analysis by setting the environment variable (this takes priority over environs flag values)")
	cmd.Flags().BoolVar(&ctl.flagTree.EnableSourceCodeUpload, "enable-source-code-upload", defaults.EnableSourceCodeUpload, "If true, enable source code upload by setting the environment variable (this takes priority over environs flag values)\n")
	cmd.Flags().StringVar(&ctl.flagTree.EnableInitContainer, "enable-init-container", defaults.EnableInitContainer, "If true, Black Duck adds init container to each service to check whether the Postgres is initialized with the databases [true|false]. This flag is supported from Black Duck version 2020.6.1 and above")

	// Extra Config Settings
	cmd.Flags().StringVar(&ctl.flagTree.NodeAffinityFilePath, "node-affinity-file-path", defaults.NodeAffinityFilePath, "Absolute path to a file containing a list of node affinities")
	cmd.Flags().StringVar(&ctl.flagTree.SecurityContextFilePath, "security-context-file-path", defaults.SecurityContextFilePath, "Absolute path to a file containing a map of pod names to security contexts runAsUser, fsGroup, and runAsGroup")
}

func isValidSize(size string) bool {
	switch strings.ToLower(size) {
	case
		"",
		"small",
		"medium",
		"large",
		"x-large":
		return true
	}
	return false
}

// CheckValuesFromFlags returns an error if a value stored in the struct will not be able to be used
func (ctl *HelmValuesFromCobraFlags) CheckValuesFromFlags(flagset *pflag.FlagSet) error {
	if FlagWasSet(flagset, "size") {
		if !isValidSize(ctl.flagTree.Size) {
			return fmt.Errorf("size must be 'small', 'medium', 'large' or 'x-large'")
		}
	}
	if FlagWasSet(flagset, "expose-ui") {
		isValid := util.IsExposeServiceValid(ctl.flagTree.ExposeService)
		if !isValid {
			return fmt.Errorf("expose ui must be '%s', '%s', '%s' or '%s'", util.NODEPORT, util.LOADBALANCER, util.OPENSHIFT, util.NONE)
		}
	}
	if FlagWasSet(flagset, "environs") {
		for _, environ := range ctl.flagTree.Environs {
			if !strings.Contains(environ, ":") {
				return fmt.Errorf("invalid environ format - NAME:VALUE")
			}
		}
	}
	if FlagWasSet(flagset, "seal-key") {
		if len(ctl.flagTree.SealKey) != 32 {
			return fmt.Errorf("seal key should be of length 32")
		}
	}
	return nil
}

// MarkRequiredFlags ...
func (ctl *HelmValuesFromCobraFlags) MarkRequiredFlags(flagset *pflag.FlagSet, version string, updating bool) error {
	if flagset.Lookup("admin-password").Changed ||
		flagset.Lookup("user-password").Changed {
		// user is explicitly required to set the postgres passwords for: 'admin', 'postgres', and 'user'
		cobra.MarkFlagRequired(flagset, "admin-password")
		cobra.MarkFlagRequired(flagset, "user-password")
	} else {
		// require all external-postgres parameters
		cobra.MarkFlagRequired(flagset, "external-postgres-host")
		cobra.MarkFlagRequired(flagset, "external-postgres-port")
		cobra.MarkFlagRequired(flagset, "external-postgres-admin")
		cobra.MarkFlagRequired(flagset, "external-postgres-user")
		cobra.MarkFlagRequired(flagset, "external-postgres-ssl")
		cobra.MarkFlagRequired(flagset, "external-postgres-admin-password")
		cobra.MarkFlagRequired(flagset, "external-postgres-user-password")
	}

	cobra.MarkFlagRequired(flagset, "seal-key")

	if util.CompareVersions(version, "2020.6.0") < 0 {
		cobra.MarkFlagRequired(flagset, "certificate-file-path")
		cobra.MarkFlagRequired(flagset, "certificate-key-file-path")
	}

	return nil
}

// VerifyChartVersionSupportsChangedFlags ...
func (ctl *HelmValuesFromCobraFlags) VerifyChartVersionSupportsChangedFlags(flagset *pflag.FlagSet, version string) error {
	if flagset.Lookup("node-port").Changed && (util.CompareVersions(version, "2020.6.0") < 0) {
		return fmt.Errorf("--node-port is not supported in Black Duck versions before 2020.6.0")
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
	foundErrors := false
	flagset.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			log.Debugf("flag '%s': CHANGED", f.Name)
			switch f.Name {
			case "version":
				util.SetHelmValueInMap(ctl.args, []string{"imageTag"}, ctl.flagTree.Version)
			case "size":
				util.SetHelmValueInMap(ctl.args, []string{"size"}, strings.ToLower(ctl.flagTree.Size))
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
			case "node-port":
				util.SetHelmValueInMap(ctl.args, []string{"exposedNodePort"}, ctl.flagTree.ExposedNodePort)
			case "environs":
				for _, value := range ctl.flagTree.Environs {
					values := strings.SplitN(value, ":", 2)
					if len(values) != 2 {
						panic(fmt.Errorf("invalid environ configuration for %s", value))
					}
					util.SetHelmValueInMap(ctl.args, []string{"environs", values[0]}, values[1])
				}
			case "enable-binary-analysis":
				util.SetHelmValueInMap(ctl.args, []string{"enableBinaryScanner"}, ctl.flagTree.EnableBinaryAnalysis)
			case "enable-source-code-upload":
				util.SetHelmValueInMap(ctl.args, []string{"enableSourceCodeUpload"}, ctl.flagTree.EnableSourceCodeUpload)
			case "external-postgres-host":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "host"}, ctl.flagTree.ExternalPostgresHost)
			case "external-postgres-port":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "port"}, ctl.flagTree.ExternalPostgresPort)
			case "external-postgres-admin":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "adminUserName"}, ctl.flagTree.ExternalPostgresAdmin)
			case "external-postgres-user":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "userUserName"}, ctl.flagTree.ExternalPostgresUser)
			case "external-postgres-ssl":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "ssl"}, strings.ToUpper(ctl.flagTree.ExternalPostgresSsl) == "TRUE")
			case "external-postgres-admin-password":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "adminPassword"}, ctl.flagTree.ExternalPostgresAdminPassword)
			case "external-postgres-user-password":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "userPassword"}, ctl.flagTree.ExternalPostgresUserPassword)
			case "pvc-storage-class":
				util.SetHelmValueInMap(ctl.args, []string{"storageClass"}, ctl.flagTree.PvcStorageClass)
			case "liveness-probes":
				util.SetHelmValueInMap(ctl.args, []string{"enableLivenessProbe"}, strings.ToUpper(ctl.flagTree.LivenessProbes) == "TRUE")
			case "enable-init-container":
				util.SetHelmValueInMap(ctl.args, []string{"enableInitContainer"}, strings.ToUpper(ctl.flagTree.EnableInitContainer) == "TRUE")
			case "persistent-storage":
				util.SetHelmValueInMap(ctl.args, []string{"enablePersistentStorage"}, strings.ToUpper(ctl.flagTree.PersistentStorage) == "TRUE")
			case "pvc-file-path":
				data, err := util.ReadFileData(ctl.flagTree.PVCFilePath)
				if err != nil {
					log.Errorf("failed to read pvc file: %+v", err)
					foundErrors = true
					return
				}
				pvcs := []blackduckv1.PVC{}
				err = json.Unmarshal([]byte(data), &pvcs)
				if err != nil {
					log.Errorf("failed to unmarshal pvc structs: %+v", err)
					foundErrors = true
					return
				}
				// Add values here if the path in Values.yaml is different than just the pvcIDName
				// ex: the pvcIDName as "postgres" but the path is postgres.something.claimSize
				// ex: the pvcIDName is "blackduck-postgres" but the path is postgres.claimSize
				pvcIDNameToHelmPath := map[string][]string{
					"blackduck-postgres":         {"postgres"},
					"blackduck-authentication":   {"authentication"},
					"blackduck-cfssl":            {"cfssl"},
					"blackduck-registration":     {"registration"},
					"blackduck-webapp":           {"webapp"},
					"blackduck-logstash":         {"logstash"},
					"blackduck-uploadcache-data": {"uploadcache"},
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
			case "deployment-resources-file-path":
				util.GetDeploymentResources(ctl.flagTree.DeploymentResourcesFilePath, ctl.args, "hubMaxMemory")
			case "node-affinity-file-path":
				data, err := util.ReadFileData(ctl.flagTree.NodeAffinityFilePath)
				if err != nil {
					log.Errorf("failed to read node affinity file: %+v", err)
					foundErrors = true
					return
				}
				nodeAffinities := map[string][]blackduckv1.NodeAffinity{}
				err = json.Unmarshal([]byte(data), &nodeAffinities)
				if err != nil {
					log.Errorf("failed to unmarshal node affinities: %+v", err)
					foundErrors = true
					return
				}

				for k, v := range nodeAffinities {
					kubeAff := OperatorAffinityToHelm(v)
					util.SetHelmValueInMap(ctl.args, []string{k, "affinity"}, kubeAff)
				}
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
				for k, v := range securityContexts {
					pathToHelmValue := []string{k, "podSecurityContext"}                  // default path for new pods
					if newPathToHelmValue, ok := securityContextIDNameToHelmPath[k]; ok { // Override the security if it's present in the list
						pathToHelmValue = newPathToHelmValue
					}
					util.SetHelmValueInMap(ctl.args, pathToHelmValue, CorePodSecurityContextToHelm(v))
				}
			case "postgres-claim-size":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "claimSize"}, ctl.flagTree.PostgresClaimSize)
			case "admin-password":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "adminPassword"}, ctl.flagTree.AdminPassword)
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "isExternal"}, false)
			case "user-password":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "userPassword"}, ctl.flagTree.UserPassword)
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "isExternal"}, false)
			case "registry":
				util.SetHelmValueInMap(ctl.args, []string{"registry"}, ctl.flagTree.Registry)
				if !ImageRegistryIsSet(ctl.flagTree.ImageRegistries, "postgresql-96-centos7") {
					util.SetHelmValueInMap(ctl.args, []string{"postgres", "registry"}, ctl.flagTree.Registry)
				}
				if !ImageRegistryIsSet(ctl.flagTree.ImageRegistries, "bdba-worker") {
					util.SetHelmValueInMap(ctl.args, []string{"binaryscanner", "registry"}, ctl.flagTree.Registry)
				}
			case "image-registries":
				SetBlackDuckImageRegistriesInHelmValuesMap(ctl.args, ctl.flagTree.ImageRegistries)
			case "pull-secret-name":
				var pullSecrets []corev1.LocalObjectReference
				for _, v := range ctl.flagTree.PullSecrets {
					pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: v})
				}
				util.SetHelmValueInMap(ctl.args, []string{"imagePullSecrets"}, pullSecrets)
			case "seal-key":
				util.SetHelmValueInMap(ctl.args, []string{"sealKey"}, ctl.flagTree.SealKey)
			default:
				log.Debugf("flag '%s': NOT FOUND", f.Name)
			}
		} else {
			log.Debugf("flag '%s': UNCHANGED", f.Name)
		}
	})

	if foundErrors {
		log.Fatalf("please fix all the above errors to continue")
	}

	return ctl.args, nil
}

// SetBlackDuckImageRegistriesInHelmValuesMap uses the image name to set the registry and tag
// in the Helm Chart for each image in imageRegistries
func SetBlackDuckImageRegistriesInHelmValuesMap(helmValues map[string]interface{}, imageRegistries []string) {
	imageNameToHelmPath := map[string][]string{
		"postgresql-96-centos7":    {"postgres"},
		"synopsys-init":            {"init"},
		"blackduck-authentication": {"authentication"},
		"bdba-worker":              {"binaryscanner"},
		"blackduck-cfssl":          {"cfssl"},
		"blackduck-documentation":  {"documentation"},
		"blackduck-jobrunner":      {"jobrunner"},
		"rabbitmq":                 {"rabbitmq"},
		"blackduck-registration":   {"registration"},
		"blackduck-scan":           {"scan"},
		"blackduck-upload-cache":   {"uploadcache"},
		"blackduck-webapp":         {"webapp"},
		"blackduck-logstash":       {"logstash"},
		"blackduck-nginx":          {"webserver"},
	}

	for _, image := range imageRegistries {
		imageName := util.ParseImageName(image)
		imageReg := util.ParseImageRepo(image)
		imageTag := util.ParseImageTag(image)

		pathToHelmValueRegistry := []string{imageName, "registry"}
		pathToHelmValueImageTag := []string{imageName, "imageTag"}
		if newPathToHelmValue, ok := imageNameToHelmPath[imageName]; ok {
			pathToHelmValueRegistry = append(newPathToHelmValue, "registry")
			pathToHelmValueImageTag = append(newPathToHelmValue, "imageTag")
		}
		util.SetHelmValueInMap(helmValues, pathToHelmValueRegistry, imageReg)
		if imageName == "postgresql-96-centos7" && imageTag != "" {
			log.Warnf("cannot set image tag for postgres with --image-registries")
		}
		util.SetHelmValueInMap(helmValues, pathToHelmValueImageTag, imageTag)
	}
}

// ImageRegistryIsSet checks if imageRegistries contains and image with the name imageName
func ImageRegistryIsSet(imageRegistries []string, imageName string) bool {
	found := false
	for _, image := range imageRegistries {
		if util.ParseImageName(image) == imageName {
			found = true
			break
		}
	}
	return found
}
