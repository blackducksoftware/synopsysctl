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

import "fmt"

// DefaultMetricsImage is the Metrics image deployed with Synopsys Operator by default
const DefaultMetricsImage string = "docker.io/prom/prometheus:v2.1.0"

// DefaultOperatorNamespace is the default namespace of Synopsys Operator
const DefaultOperatorNamespace string = "synopsys-operator"

// Default Base Specs for Create
const defaultBaseAlertSpec string = "default"
const defaultBaseBlackDuckSpec string = "persistentStorageLatest"
const defaultBaseOpsSightSpec string = "default"

// busybox image
const defaultBusyBoxImage string = "docker.io/busybox:1.28"

// flag for all namespaces
const allNamespacesFlag string = "--all-namespaces"

const (
	clusterTypeKubernetes = "KUBERNETES"
	clusterTypeOpenshift  = "OPENSHIFT"
)

var nativeClusterType = clusterTypeKubernetes

var baseChartRepository = "https://sig-repo.synopsys.com/sig-cloudnative"

// AlertPostSuffix adds "-alert" to the end of the release (to differentiate if other apps are given the same name - ex: BlackDuck and Alert are both named "bd")
const AlertPostSuffix = "-alert"

// Alert Helm Chart Constants
var alertVersion = "5.3.1"
var alertChartName = "synopsys-alert"
var alertChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, alertChartName, alertVersion)

// Opssight Helm Chart Constants
var opssightVersion = "2.2.5"
var opssightChartName = "opssight"
var opssightChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, opssightChartName, opssightVersion)

// Black Duck Helm Chart Constants
var blackDuckVersion = "2020.4.0"
var blackDuckChartName = "blackduck"
var blackduckChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, blackDuckChartName, blackDuckVersion)

// Polaris Helm Chart Constants
var polarisName = "polaris"
var polarisVersion = "2020.03"
var polarisChartName = "polaris-helmchart"
var polarisChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, polarisChartName, polarisVersion)

// Polaris Reporting Helm Chart Constants
var polarisReportingName = "polaris-reporting"
var polarisReportingVersion = "2020.03"
var polarisReportingChartName = "polaris-helmchart-reporting"
var polarisReportingChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, polarisReportingChartName, polarisReportingVersion)

// BDBA Helm Chart Constants
var bdbaName = "bdba"
var bdbaVersion = "2020.03"
var bdbaChartName = "bdba"
var bdbaChartRepository = fmt.Sprintf("%s/%s-%s.tgz", baseChartRepository, bdbaChartName, bdbaVersion)
