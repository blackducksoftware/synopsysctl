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

package blackduck

import (
	"fmt"
	"strings"

	"github.com/blackducksoftware/synopsysctl/pkg/api"
	"github.com/blackducksoftware/synopsysctl/pkg/util"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// CRUDServiceOrRoute will create or update Black Duck exposed service or route in case of OpenShift
func CRUDServiceOrRoute(restConfig *rest.Config, kubeClient *kubernetes.Clientset, namespace string, name string, isExposedUI interface{}, exposedServiceType interface{}) error {
	serviceName := util.GetResourceName(name, util.BlackDuckName, "webserver-exposed")
	routeName := util.GetResourceName(name, util.BlackDuckName, "")
	isOpenShift := util.IsOpenshift(kubeClient)
	var err error
	if isExposedUI != nil && isExposedUI.(bool) {
		switch exposedServiceType.(string) {
		case util.NODEPORT:
			err = crudExposedService(restConfig, kubeClient, namespace, name, corev1.ServiceTypeNodePort)
			if err != nil {
				return err
			}
		case util.LOADBALANCER:
			err = crudExposedService(restConfig, kubeClient, namespace, name, corev1.ServiceTypeLoadBalancer)
			if err != nil {
				return err
			}
		case util.OPENSHIFT:
			if _, err = util.GetService(kubeClient, namespace, serviceName); err == nil {
				err = util.DeleteService(kubeClient, namespace, serviceName)
				if err != nil {
					return fmt.Errorf("unable to delete the Black Duck webserver expose service due to %+v", err)
				}
			}
			routeClient := util.GetRouteClient(restConfig, kubeClient, namespace)
			if _, err = util.GetRoute(routeClient, namespace, routeName); err != nil && !k8serrors.IsAlreadyExists(err) {
				openShiftRoute := GetWebServerRoute(namespace, routeName, name)
				_, err := util.CreateRoute(routeClient, namespace, openShiftRoute)
				if err != nil {
					return fmt.Errorf("failed to create Black Duck webserver route due to %+v", err)
				}
			}
		}
	} else {
		if isOpenShift {
			routeClient := util.GetRouteClient(restConfig, kubeClient, namespace)
			if _, err = util.GetRoute(routeClient, namespace, routeName); err == nil {
				err = util.DeleteRoute(routeClient, namespace, routeName)
				if err != nil {
					return fmt.Errorf("unable to delete Black Duck webserver route due to %+v", err)
				}
			}
		} else {
			if _, err = util.GetService(kubeClient, namespace, serviceName); err == nil {
				err = util.DeleteService(kubeClient, namespace, serviceName)
				if err != nil {
					return fmt.Errorf("unable to delete the Black Duck webserver expose service due to %+v", err)
				}
			}
		}
	}
	return nil
}

// crudExposedService crud for webserver exposed service
func crudExposedService(restConfig *rest.Config, kubeClient *kubernetes.Clientset, namespace string, name string, serviceType corev1.ServiceType) error {
	serviceName := util.GetResourceName(name, util.BlackDuckName, "webserver-exposed")
	routeName := util.GetResourceName(name, util.BlackDuckName, "")
	isOpenShift := util.IsOpenshift(kubeClient)
	if isOpenShift {
		routeClient := util.GetRouteClient(restConfig, kubeClient, namespace)
		if _, err := util.GetRoute(routeClient, namespace, routeName); err == nil {
			err = util.DeleteRoute(routeClient, namespace, routeName)
			if err != nil {
				return fmt.Errorf("unable to delete Black Duck webserver route due to %+v", err)
			}
		}
	}
	if svc, err := util.GetService(kubeClient, namespace, serviceName); err == nil {
		if !strings.EqualFold(string(svc.Spec.Type), string(serviceType)) {
			svc.Spec.Type = serviceType
			if _, err = util.UpdateService(kubeClient, namespace, svc); err != nil {
				return fmt.Errorf("failed to update Black Duck webserver exposed service due to %+v", err)
			}
		}
	} else {
		service := GetWebServerExposedService(namespace, serviceName, name, serviceType)
		_, err = util.CreateKubeService(kubeClient, namespace, service)
		if err != nil {
			return fmt.Errorf("failed to create Black Duck webserver exposed service due to %+v", err)
		}
	}
	return nil
}

// GetWebServerExposedService return the Kubernetes service
func GetWebServerExposedService(namespace string, serviceName string, name string, serviceType corev1.ServiceType) *corev1.Service {
	return util.GetKubeService(
		namespace,
		serviceName,
		map[string]string{
			"app":       util.BlackDuckName,
			"component": "webserver-exposed",
			"name":      name,
		},
		map[string]string{
			"app":       util.BlackDuckName,
			"component": "webserver",
			"name":      name,
		},
		int32(443),
		"8443",
		serviceType,
	)
}

// GetWebServerRoute return the OpenShift route
func GetWebServerRoute(namespace string, routeName string, name string) *routev1.Route {
	return util.GetRouteComponent(
		&api.Route{
			Name:               routeName,
			Namespace:          namespace,
			Kind:               "Service",
			ServiceName:        util.GetResourceName(name, util.BlackDuckName, "webserver"),
			PortName:           fmt.Sprintf("port-%d", 443),
			Labels:             map[string]string{"app": util.BlackDuckName, "name": name, "component": "route"},
			TLSTerminationType: routev1.TLSTerminationPassthrough,
		},
		map[string]string{"app": util.BlackDuckName, "name": name, "component": "route"},
	)
}
