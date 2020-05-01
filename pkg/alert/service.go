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

package alert

import (
	"fmt"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// CRUDServiceOrRoute will create or update Alert exposed service, or route in case of OpenShift
func CRUDServiceOrRoute(restConfig *rest.Config, kubeClient *kubernetes.Clientset, namespace string, customerAppName string, isExposedUI interface{}, exposedServiceType interface{}, isChanged bool) error {
	serviceName := util.GetResourceName(customerAppName, util.AlertName, "exposed")
	routeName := util.GetResourceName(customerAppName, util.AlertName, "")
	isOpenShift := util.IsOpenshift(kubeClient)
	var err error
	if isExposedUI != nil && isExposedUI.(bool) {
		switch exposedServiceType.(string) {
		case "NodePort":
			err = crudExposedService(restConfig, kubeClient, namespace, customerAppName, corev1.ServiceTypeNodePort)
			if err != nil {
				return err
			}
		case "LoadBalancer":
			err = crudExposedService(restConfig, kubeClient, namespace, customerAppName, corev1.ServiceTypeLoadBalancer)
			if err != nil {
				return err
			}
		case "OpenShift":
			if svc, err := util.GetService(kubeClient, namespace, serviceName); err == nil {
				svc.Labels = util.InitLabels(svc.Labels)
				if _, ok := svc.Labels["helm.sh/chart"]; !ok {
					err = util.DeleteService(kubeClient, namespace, serviceName)
					if err != nil {
						return fmt.Errorf("unable to delete the Alert's expose service due to %+v", err)
					}
				}
			}
		}
	} else {
		if isChanged {
			if isOpenShift {
				routeClient := util.GetRouteClient(restConfig, kubeClient, namespace)
				if _, err = util.GetRoute(routeClient, namespace, routeName); err == nil {
					err = util.DeleteRoute(routeClient, namespace, routeName)
					if err != nil {
						return fmt.Errorf("unable to delete Alert's route due to %+v", err)
					}
				}
			} else {
				if _, err = util.GetService(kubeClient, namespace, serviceName); err == nil {
					err = util.DeleteService(kubeClient, namespace, serviceName)
					if err != nil {
						return fmt.Errorf("unable to delete the Alert's expose service due to %+v", err)
					}
				}
			}
		}
	}
	return nil
}

// crudExposedService crud for webserver exposed service
func crudExposedService(restConfig *rest.Config, kubeClient *kubernetes.Clientset, namespace string, customerAppName string, serviceType corev1.ServiceType) error {
	serviceName := util.GetResourceName(customerAppName, util.AlertName, "exposed")
	routeName := util.GetResourceName(customerAppName, util.AlertName, "")
	if util.IsOpenshift(kubeClient) {
		routeClient := util.GetRouteClient(restConfig, kubeClient, namespace)
		if route, err := util.GetRoute(routeClient, namespace, routeName); err == nil {
			route.Labels = util.InitLabels(route.Labels)
			if _, ok := route.Labels["helm.sh/chart"]; !ok {
				err = util.DeleteRoute(routeClient, namespace, routeName)
				if err != nil {
					return fmt.Errorf("unable to delete Alert's route due to %+v", err)
				}
			}
		}
	}
	if svc, err := util.GetService(kubeClient, namespace, serviceName); err == nil {
		svc.Labels = util.InitLabels(svc.Labels)
		if _, ok := svc.Labels["helm.sh/chart"]; !ok && !strings.EqualFold(string(svc.Spec.Type), string(serviceType)) {
			if err = util.DeleteService(kubeClient, namespace, svc.Name); err != nil {
				return fmt.Errorf("failed to delete Alert's service due to %+v", err)
			}
		}
	}
	return nil
}
