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
)

// BaseChartRepository ...
var BaseChartRepository = "https://sig-repo.synopsys.com/sig-cloudnative"

/* Alert Helm Chart Constants */

// AlertVersion ...
var AlertVersion = "5.3.2"

// AlertChartName ...
var AlertChartName = "synopsys-alert"

// AlertChartRepository ...
var AlertChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, AlertChartName, AlertVersion)

/* Opssight Helm Chart Constants */

// OpsSightVersionToChartVersion ...
var OpsSightVersionToChartVersion = map[string]string{
	"2.2.5": "2.2.5-1",
}

// OpsSightVersion ...
var OpsSightVersion = "2.2.5"

// OpsSightChartName ..
var OpsSightChartName = "opssight"

// OpsSightChartRepository ...
var OpsSightChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, OpsSightChartName, OpsSightVersion)

/* Black Duck Helm Chart Constants */

// BlackDuckVersion ...
var BlackDuckVersion = "2020.4.1"

// BlackDuckChartName ...
var BlackDuckChartName = "blackduck"

// BlackDuckChartRepository ...
var BlackDuckChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, BlackDuckChartName, BlackDuckVersion)

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
var PolarisReportingVersion = "2020.04"

// PolarisReportingChartName ...
var PolarisReportingChartName = "polaris-helmchart-reporting"

// PolarisReportingChartRepository ...
var PolarisReportingChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, PolarisReportingChartName, PolarisReportingVersion)

/* BDBA Helm Chart Constants */

// BDBAName ...
var BDBAName = "bdba"

// BDBAVersion ...
var BDBAVersion = "2020.03"

// BDBAChartName ...
var BDBAChartName = "bdba"

// BDBAChartRepository ...
var BDBAChartRepository = fmt.Sprintf("%s/%s-%s.tgz", BaseChartRepository, BDBAChartName, BDBAVersion)
