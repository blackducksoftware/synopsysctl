/*
Copyright (C) 2020 Synopsys, Inc.

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

package globals

import (
	"fmt"

	"github.com/blackducksoftware/synopsysctl/pkg/util"

	// get auth clients for gcp
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// BaseChartRepository ...
var BaseChartRepository = "https://sig-repo.synopsys.com/sig-cloudnative"

// IndexChartURLs ...
var IndexChartURLs = []string{}

/* Alert Helm Chart Constants */

// AlertVersion ...
var AlertVersion = ""

// AlertChartName ...
var AlertChartName = "synopsys-alert"

// AlertChartRepository ...
var AlertChartRepository = ""

/* Opssight Helm Chart Constants */

// OpsSightVersion ...
var OpsSightVersion = ""

// OpsSightChartName ..
var OpsSightChartName = "blackduck-connector"

// OpsSightChartRepository ...
var OpsSightChartRepository = ""

/* Black Duck Helm Chart Constants */

// BlackDuckVersion ...
var BlackDuckVersion = ""

// BlackDuckChartName ...
var BlackDuckChartName = "blackduck"

// BlackDuckChartRepository ...
var BlackDuckChartRepository = ""

/* Polaris Helm Chart Constants */

// PolarisName ...
var PolarisName = "polaris"

// PolarisVersion ...
var PolarisVersion = "2020.03"

// PolarisChartName ...
var PolarisChartName = "polaris-helmchart"

// PolarisChartRepository ...
var PolarisChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, PolarisChartName, PolarisVersion)

/* Polaris Reporting Helm Chart Constants */

// PolarisReportingName ...
var PolarisReportingName = "polaris-reporting"

// PolarisReportingVersion ...
var PolarisReportingVersion = ""

// PolarisReportingChartName ...
var PolarisReportingChartName = "polaris-helmchart-reporting"

// PolarisReportingChartRepository ...
var PolarisReportingChartRepository = ""

/* BDBA Helm Chart Constants */

// BDBAName ...
var BDBAName = "bdba"

// BDBAVersion ...
var BDBAVersion = ""

// BDBAChartName ...
var BDBAChartName = "bdba"

// BDBAChartRepository ...
var BDBAChartRepository = ""

func init() {
	IndexChartURLs, _ = util.GetChartURLs(BaseChartRepository, "")

	// Alert
	AlertChartRepository, _ = util.GetLatestChartURLForApp(IndexChartURLs, AlertChartName)
	alertPackageNameSlice := util.ParsePackageName(AlertChartRepository)
	AlertVersion = alertPackageNameSlice[1]

	// Black Duck
	BlackDuckChartRepository, _ = util.GetLatestChartURLForApp(IndexChartURLs, BlackDuckChartName)
	blackDuckPackageNameSlice := util.ParsePackageName(BlackDuckChartRepository)
	BlackDuckVersion = blackDuckPackageNameSlice[1]

	// BDBA
	BDBAChartRepository, _ = util.GetLatestChartURLForApp(IndexChartURLs, BDBAChartName)
	BDBAPackageNameSlice := util.ParsePackageName(BDBAChartRepository)
	BDBAVersion = BDBAPackageNameSlice[1]

	// OpsSight (aka Black Duck Connector)
	OpsSightChartRepository, _ = util.GetLatestChartURLForApp(IndexChartURLs, OpsSightChartName)
	OpsSightPackageNameSlice := util.ParsePackageName(OpsSightChartRepository)
	OpsSightVersion = OpsSightPackageNameSlice[1]

	// Polaris
	// TODO ...

	// Polaris Reporting
	PolarisReportingChartRepository, _ = util.GetLatestChartURLForApp(IndexChartURLs, PolarisReportingChartName)
	PolarisReportingPackageNameSlice := util.ParsePackageName(PolarisReportingChartRepository)
	PolarisReportingVersion = PolarisReportingPackageNameSlice[1]

}
