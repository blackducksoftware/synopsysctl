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

// DefaultBusyBoxImage ...
var DefaultBusyBoxImage = "docker.io/busybox:1.28"

// AllNamespacesFlag ...
const AllNamespacesFlag string = "--all-namespaces"

const (
	// ClusterTypeKubernetes ...
	ClusterTypeKubernetes = "KUBERNETES"
	// ClusterTypeOpenshift ...
	ClusterTypeOpenshift = "OPENSHIFT"
)

// NativeClusterType ...
var NativeClusterType = ClusterTypeKubernetes

// AlertPostSuffix adds "-alert" to the end of the release (to differentiate if other apps are given the same name - ex: BlackDuck and Alert are both named "bd")
const AlertPostSuffix = "-alert"
