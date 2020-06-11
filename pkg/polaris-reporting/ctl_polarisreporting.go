/*
 * Copyright (C) 2020 Synopsys, Inc.
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

package polarisreporting

import (
	"fmt"
	"strconv"

	"github.com/blackducksoftware/synopsysctl/pkg/globals"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	Version                   string
	FQDN                      string
	GCPServiceAccountFilePath string
	IngressClass              string
	StorageClass              string
	ReportStorageSize         string
	EventstoreSize            string
	PostgresInternal          string
	PostgresHost              string
	PostgresPort              int
	PostgresUsername          string
	PostgresPassword          string
	PostgresSize              string
	PostgresSSLMode           string
	SMTPHost                  string
	SMTPPort                  int
	SMTPUsername              string
	SMTPPassword              string
	SMTPSenderEmail           string
	SMTPTlsMode               string
	SMTPTlsIgnoreInvalidCert  string
	SMTPTlsTrustedHosts       string
}

// DefaultFlagTree ...
// [Dev Note]: These should match the Helm Chart's Values.yaml
var DefaultFlagTree = FlagTree{
	// version
	Version: globals.PolarisReportingVersion,
	// domain specific flags
	IngressClass: "nginx",
	// license related flags
	// storage related flags
	ReportStorageSize: "5Gi",
	EventstoreSize:    "50Gi",
	// smtp related flags
	// postgres specific flags
	PostgresInternal: "false",
	PostgresPort:     5432,
	PostgresSSLMode:  "require",
	PostgresSize:     "50Gi",
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

	// Version
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.Version, "version", DefaultFlagTree.Version, "Version of Polaris-Reporting you want to install\n")
	} else {
		cmd.Flags().StringVar(&ctl.flagTree.Version, "version", "", "Version of Polaris-Reporting you want to install\n")
	}

	// domain specific flags
	cmd.Flags().StringVar(&ctl.flagTree.FQDN, "fqdn", ctl.flagTree.FQDN, "Fully qualified domain name [Example: \"example.polaris.synopsys.com\"]")
	cmd.Flags().StringVar(&ctl.flagTree.IngressClass, "ingress-class", DefaultFlagTree.IngressClass, "Name of ingress class\n")
	if master {
		cobra.MarkFlagRequired(cmd.Flags(), "fqdn")
	}

	// license related flags
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.GCPServiceAccountFilePath, "gcp-service-account-path", "", "Absolute path to given Google Cloud Platform service account for pulling images\n")
		cobra.MarkFlagRequired(cmd.Flags(), "gcp-service-account-path")
	}

	// storage related flags
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.ReportStorageSize, "reportstorage-size", DefaultFlagTree.ReportStorageSize, "Persistent Volume Claim size for reportstorage")
		cmd.Flags().StringVar(&ctl.flagTree.EventstoreSize, "eventstore-size", DefaultFlagTree.EventstoreSize, "Persistent Volume Claim size for eventstore")
		cmd.Flags().StringVar(&ctl.flagTree.StorageClass, "storage-class", ctl.flagTree.StorageClass, "Storage Class for all Polaris-Reporting's storage\n")
		// TODO: Once the Helm charts are fixed for the storage class issue, we can remove the required flag for storage class
		cobra.MarkFlagRequired(cmd.Flags(), "storage-class")
	}

	// smtp related flags
	cmd.Flags().StringVar(&ctl.flagTree.SMTPHost, "smtp-host", ctl.flagTree.SMTPHost, "SMTP host")
	cmd.Flags().IntVar(&ctl.flagTree.SMTPPort, "smtp-port", ctl.flagTree.SMTPPort, "SMTP port")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPUsername, "smtp-username", ctl.flagTree.SMTPUsername, "SMTP username")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPPassword, "smtp-password", ctl.flagTree.SMTPPassword, "SMTP password")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPSenderEmail, "smtp-sender-email", ctl.flagTree.SMTPSenderEmail, "SMTP sender email")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPTlsMode, "smtp-tls-mode", ctl.flagTree.SMTPTlsMode, "SMTP TLS mode [disable|try-starttls|require-starttls|require-tls]")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPTlsTrustedHosts, "smtp-trusted-hosts", ctl.flagTree.SMTPTlsTrustedHosts, "Whitespace separated list of trusted hosts")
	cmd.Flags().StringVar(&ctl.flagTree.SMTPTlsIgnoreInvalidCert, "insecure-skip-smtp-tls-verify", "false", "SMTP server's certificates won't be validated\n")

	if master {
		cobra.MarkFlagRequired(cmd.Flags(), "smtp-host")
		cobra.MarkFlagRequired(cmd.Flags(), "smtp-port")
		cobra.MarkFlagRequired(cmd.Flags(), "smtp-username")
		cobra.MarkFlagRequired(cmd.Flags(), "smtp-password")
		cobra.MarkFlagRequired(cmd.Flags(), "smtp-sender-email")
	}

	// postgres specific flags
	cmd.Flags().StringVar(&ctl.flagTree.PostgresInternal, "enable-postgres-container", DefaultFlagTree.PostgresInternal, "If true, synopsysctl will deploy a postgres container backed by persistent volume (Not recommended for production usage)")
	cmd.Flags().StringVar(&ctl.flagTree.PostgresHost, "postgres-host", ctl.flagTree.PostgresHost, "Postgres host. If --enable-postgres-container=true, the default is \"postgres\"")
	cmd.Flags().IntVar(&ctl.flagTree.PostgresPort, "postgres-port", DefaultFlagTree.PostgresPort, "Postgres port")
	cmd.Flags().StringVar(&ctl.flagTree.PostgresUsername, "postgres-username", ctl.flagTree.PostgresUsername, "Postgres username. If --enable-postgres-container=true, the default is \"postgres\"")
	cmd.Flags().StringVar(&ctl.flagTree.PostgresPassword, "postgres-password", ctl.flagTree.PostgresPassword, "Postgres password")
	cmd.Flags().StringVar(&ctl.flagTree.PostgresSSLMode, "postgres-ssl-mode", DefaultFlagTree.PostgresSSLMode, "Postgres ssl mode [disable|require]")
	if master {
		cmd.Flags().StringVar(&ctl.flagTree.PostgresSize, "postgres-size", DefaultFlagTree.PostgresSize, "Persistent volume claim size to use for postgres. Only applicable if --enable-postgres-container is set to true\n")
	}

	if master {
		cobra.MarkFlagRequired(cmd.Flags(), "postgres-password")
	}
}

// CheckValuesFromFlags returns an error if a value set by a flag is invalid
func (ctl *HelmValuesFromCobraFlags) CheckValuesFromFlags(flagset *pflag.FlagSet) error {
	return nil
}

// GenerateHelmFlagsFromCobraFlags checks each flag in synopsysctl and updates the map to
// contain the corresponding helm chart field and value
func (ctl *HelmValuesFromCobraFlags) GenerateHelmFlagsFromCobraFlags(flagset *pflag.FlagSet) (map[string]interface{}, error) {
	err := ctl.CheckValuesFromFlags(flagset)
	if err != nil {
		return nil, err
	}
	var isErrorExist bool
	util.SetHelmValueInMap(ctl.args, []string{"global", "environment"}, "onprem")
	// TODO: Need to remove it as part of 2020.4.0. It's a work around to fix the report storage chart issue
	util.SetHelmValueInMap(ctl.args, []string{"rp-storage-service", "environment"}, "onprem")
	flagset.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			log.Debugf("flag '%s': CHANGED", f.Name)
			switch f.Name {
			case "fqdn":
				util.SetHelmValueInMap(ctl.args, []string{"global", "rootDomain"}, ctl.flagTree.FQDN)
			case "gcp-service-account-path":
				data, err := util.ReadFileData(ctl.flagTree.GCPServiceAccountFilePath)
				if err != nil {
					log.Errorf("failed to read gcp service account file at path: %s, error: %+v", ctl.flagTree.GCPServiceAccountFilePath, err)
					isErrorExist = true
				}
				util.SetHelmValueInMap(ctl.args, []string{"imageCredentials", "password"}, data)
			case "ingress-class":
				util.SetHelmValueInMap(ctl.args, []string{"ingressClass"}, ctl.flagTree.IngressClass)
			case "storage-class":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "storageClass"}, ctl.flagTree.StorageClass)
				util.SetHelmValueInMap(ctl.args, []string{"eventstore", "persistence", "storageClass"}, ctl.flagTree.StorageClass)
				util.SetHelmValueInMap(ctl.args, []string{"rp-storage-service", "report-storage", "volume", "storageClass"}, ctl.flagTree.StorageClass)
			case "eventstore-size":
				util.SetHelmValueInMap(ctl.args, []string{"eventstore", "persistence", "size"}, ctl.flagTree.EventstoreSize)
			case "reportstorage-size":
				util.SetHelmValueInMap(ctl.args, []string{"rp-storage-service", "report-storage", "volume", "size"}, ctl.flagTree.ReportStorageSize)
			case "smtp-host":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "smtp", "host"}, ctl.flagTree.SMTPHost)
			case "smtp-port":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "smtp", "port"}, fmt.Sprintf("%d", ctl.flagTree.SMTPPort))
			case "smtp-username":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "smtp", "user"}, ctl.flagTree.SMTPUsername)
			case "smtp-password":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "smtp", "password"}, ctl.flagTree.SMTPPassword)
			case "smtp-sender-email":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "smtp", "sender_email"}, ctl.flagTree.SMTPSenderEmail)
			case "smtp-tls-mode":
				var tlsMode SMTPTLSMode
				switch SMTPTLSMode(ctl.flagTree.SMTPTlsMode) {
				case SMTPTLSModeDisable:
					tlsMode = SMTPTLSModeDisable
				case SMTPTLSModeTryStartTLS:
					tlsMode = SMTPTLSModeTryStartTLS
				case SMTPTLSModeRequireStartTLS:
					tlsMode = SMTPTLSModeRequireStartTLS
				case SMTPTLSModeRequireTLS:
					tlsMode = SMTPTLSModeRequireTLS
				default:
					log.Errorf("%s is an invalid value for --smtp-tls-mode", ctl.flagTree.SMTPTlsMode)
					isErrorExist = true
				}
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "auth-server", "smtp", "tls_mode"}, tlsMode)
			case "smtp-trusted-hosts":
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "auth-server", "smtp", "tls_trusted_hosts"}, ctl.flagTree.SMTPTlsTrustedHosts)
			case "insecure-skip-smtp-tls-verify":
				b, _ := strconv.ParseBool(ctl.flagTree.SMTPTlsIgnoreInvalidCert)
				util.SetHelmValueInMap(ctl.args, []string{"onprem-auth-service", "auth-server", "smtp", "tls_check_server_identity"}, !b)
			case "enable-postgres-container":
				// If using external postgres, host and username must be set
				if ctl.flagTree.PostgresInternal == "false" {
					if len(ctl.flagTree.PostgresHost) == 0 {
						log.Errorf("you must set external postgres database postgres-host")
						isErrorExist = true
					}
					if len(ctl.flagTree.PostgresUsername) == 0 {
						log.Errorf("you must set external postgres database postgres-host")
						isErrorExist = true
					}
				}
				b, _ := strconv.ParseBool(ctl.flagTree.PostgresInternal)
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "isExternal"}, !b)
			case "postgres-host":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "host"}, ctl.flagTree.PostgresHost)
			case "postgres-port":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "port"}, fmt.Sprintf("%d", ctl.flagTree.PostgresPort))
			case "postgres-username":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "user"}, ctl.flagTree.PostgresUsername)
			case "postgres-password":
				if len(ctl.flagTree.PostgresPassword) == 0 {
					log.Errorf("you must set postgres-password")
					isErrorExist = true
				}
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "password"}, ctl.flagTree.PostgresPassword)
			case "postgres-size":
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "size"}, ctl.flagTree.PostgresSize)
			case "postgres-ssl-mode":
				var sslMode PostgresSSLMode
				switch PostgresSSLMode(ctl.flagTree.PostgresSSLMode) {
				case PostgresSSLModeDisable:
					sslMode = PostgresSSLModeDisable
				//case PostgresSSLModeAllow:
				//  ctl.args["postgres.sslMode"] = fmt.Sprintf("%s", PostgresSSLModeAllow)
				//case PostgresSSLModePrefer:
				//  ctl.args["postgres.sslMode"] = fmt.Sprintf("%s", PostgresSSLModePrefer)
				case PostgresSSLModeRequire:
					sslMode = PostgresSSLModeRequire
				default:
					log.Errorf("%s is an invalid value for --postgres-ssl-mode", ctl.flagTree.PostgresSSLMode)
					isErrorExist = true
				}
				util.SetHelmValueInMap(ctl.args, []string{"postgres", "sslMode"}, sslMode)
			default:
				log.Debugf("flag '%s': NOT FOUND", f.Name)
			}
		}
	})

	if isErrorExist {
		log.Fatalf("please fix all the above errors to continue")
	}

	return ctl.args, nil
}
