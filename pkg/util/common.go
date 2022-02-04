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

package util

import (
	"context"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/blackducksoftware/synopsysctl/pkg/api"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	securityclient "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/api/storage/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// OPENSHIFT denotes to create an OpenShift routes
	OPENSHIFT = "OPENSHIFT"
	// NONE denotes no exposed service
	NONE = "NONE"
	// NODEPORT denotes to create a NodePort service
	NODEPORT = "NODEPORT"
	// LOADBALANCER denotes to create a LoadBalancer service
	LOADBALANCER = "LOADBALANCER"
)

// CreateSecretFromFile will create the secret from file
func CreateSecretFromFile(clientset *kubernetes.Clientset, jsonFile string, namespace string, name string, dataKey string) (*corev1.Secret, error) {
	file, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		log.Panicf("Unable to read the secret file %s due to error: %v\n", jsonFile, err)
	}

	return clientset.CoreV1().Secrets(namespace).Create(context.TODO(), &corev1.Secret{
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{dataKey: string(file)},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, metav1.CreateOptions{})
}

// CreateSecret will create the secret
func CreateSecret(clientset *kubernetes.Clientset, namespace string, name string, stringData map[string]string) (*corev1.Secret, error) {
	return clientset.CoreV1().Secrets(namespace).Create(context.TODO(), &corev1.Secret{
		Type:       corev1.SecretTypeOpaque,
		StringData: stringData,
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, metav1.CreateOptions{})
}

// GetSecret will create the secret
func GetSecret(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.Secret, error) {
	return clientset.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListSecrets will list the secret
func ListSecrets(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.SecretList, error) {
	return clientset.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateSecret updates a secret
func UpdateSecret(clientset *kubernetes.Clientset, namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	return clientset.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
}

// DeleteSecret will delete the secret
func DeleteSecret(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.CoreV1().Secrets(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetConfigMap will get the config map
func GetConfigMap(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.ConfigMap, error) {
	return clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListConfigMaps will list the config map
func ListConfigMaps(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.ConfigMapList, error) {
	return clientset.CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateConfigMap updates a config map
func UpdateConfigMap(clientset *kubernetes.Clientset, namespace string, configMap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	return clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
}

// DeleteConfigMap will delete the config map
func DeleteConfigMap(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.CoreV1().ConfigMaps(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// CreateNamespace will create the namespace
func CreateNamespace(clientset *kubernetes.Clientset, namespace string) (*corev1.Namespace, error) {
	return clientset.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      namespace,
		},
	}, metav1.CreateOptions{})
}

// GetNamespace will get the namespace
func GetNamespace(clientset *kubernetes.Clientset, namespace string) (*corev1.Namespace, error) {
	return clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
}

// ListNamespaces will list the namespace
func ListNamespaces(clientset *kubernetes.Clientset, labelSelector string) (*corev1.NamespaceList, error) {
	return clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateNamespace updates a namespace
func UpdateNamespace(clientset *kubernetes.Clientset, namespace *corev1.Namespace) (*corev1.Namespace, error) {
	return clientset.CoreV1().Namespaces().Update(context.TODO(), namespace, metav1.UpdateOptions{})
}

// DeleteNamespace will delete the namespace
func DeleteNamespace(clientset *kubernetes.Clientset, namespace string) error {
	return clientset.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})
}

// GetPod will get the input pods corresponding to a namespace
func GetPod(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.Pod, error) {
	return clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListPods will get all the pods corresponding to a namespace
func ListPods(clientset *kubernetes.Clientset, namespace string) (*corev1.PodList, error) {
	return clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
}

// ListPodsWithLabels will get all the pods corresponding to a namespace and labels
func ListPodsWithLabels(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.PodList, error) {
	return clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// DeletePod will delete the input pods corresponding to a namespace
func DeletePod(clientset *kubernetes.Clientset, namespace string, name string) error {
	propagationPolicy := metav1.DeletePropagationBackground
	return clientset.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}

// GetReplicationController will get the replication controller corresponding to a namespace and name
func GetReplicationController(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.ReplicationController, error) {
	return clientset.CoreV1().ReplicationControllers(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListReplicationControllers will get the replication controllers corresponding to a namespace
func ListReplicationControllers(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.ReplicationControllerList, error) {
	return clientset.CoreV1().ReplicationControllers(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateReplicationController updates the replication controller
func UpdateReplicationController(clientset *kubernetes.Clientset, namespace string, rc *corev1.ReplicationController) (*corev1.ReplicationController, error) {
	return clientset.CoreV1().ReplicationControllers(namespace).Update(context.TODO(), rc, metav1.UpdateOptions{})
}

// DeleteReplicationController will delete the replication controller corresponding to a namespace and name
func DeleteReplicationController(clientset *kubernetes.Clientset, namespace string, name string) error {
	propagationPolicy := metav1.DeletePropagationBackground
	return clientset.CoreV1().ReplicationControllers(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}

// GetDeployment will get the deployment corresponding to a namespace and name
func GetDeployment(clientset *kubernetes.Clientset, namespace string, name string) (*appsv1.Deployment, error) {
	return clientset.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListDeployments will get all the deployments corresponding to a namespace
func ListDeployments(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*appsv1.DeploymentList, error) {
	return clientset.AppsV1().Deployments(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateDeployment updates the deployment
func UpdateDeployment(clientset *kubernetes.Clientset, namespace string, deployment *appsv1.Deployment) (*appsv1.Deployment, error) {
	return clientset.AppsV1().Deployments(namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
}

// DeleteDeployment will delete the deployment corresponding to a namespace and name
func DeleteDeployment(clientset *kubernetes.Clientset, namespace string, name string) error {
	propagationPolicy := metav1.DeletePropagationBackground
	return clientset.AppsV1().Deployments(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}

// CreatePersistentVolume will create the persistent volume
func CreatePersistentVolume(clientset *kubernetes.Clientset, name string, storageClass string, claimSize string, nfsPath string, nfsServer string) (*corev1.PersistentVolume, error) {
	pvQuantity, _ := resource.ParseQuantity(claimSize)
	return clientset.CoreV1().PersistentVolumes().Create(context.TODO(), &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: name,
			Name:      name,
		},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:         map[corev1.ResourceName]resource.Quantity{corev1.ResourceStorage: pvQuantity},
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: storageClass,
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				NFS: &corev1.NFSVolumeSource{
					Path:   nfsPath,
					Server: nfsServer,
				},
			},
		},
	}, metav1.CreateOptions{})
}

// DeletePersistentVolume will delete the persistent volume
func DeletePersistentVolume(clientset *kubernetes.Clientset, name string) error {
	return clientset.CoreV1().PersistentVolumes().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// FilterPodByNamePrefixInNamespace will filter the pod based on pod name prefix from a list a pods in a given namespace
func FilterPodByNamePrefixInNamespace(clientset *kubernetes.Clientset, namespace string, prefix string) (*corev1.Pod, error) {
	pods, err := ListPods(clientset, namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to list the pods in namespace %s due to %+v", namespace, err)
	}

	pod := FilterPodByNamePrefix(pods, prefix)
	if pod != nil {
		return pod, nil
	}
	return nil, fmt.Errorf("unable to find the pod with prefix %s", prefix)
}

// FilterPodByNamePrefix will filter the pod based on pod name prefix from a list a pods
func FilterPodByNamePrefix(pods *corev1.PodList, prefix string) *corev1.Pod {
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, prefix) {
			return &pod
		}
	}
	return nil
}

// GetService will get the service information for the input service name inside the input namespace
func GetService(clientset *kubernetes.Clientset, namespace string, serviceName string) (*corev1.Service, error) {
	return clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
}

// ListServices will list the service information for the input service name inside the input namespace
func ListServices(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.ServiceList, error) {
	return clientset.CoreV1().Services(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// GetKubeService will get the kubernetes service
func GetKubeService(namespace string, name string, labels map[string]string, selector map[string]string, port int32, target string, serviceType corev1.ServiceType) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       fmt.Sprintf("port-%d", port),
					Port:       port,
					TargetPort: intstr.Parse(target),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type:     serviceType,
			Selector: selector,
		},
	}
}

// CreateKubeService will create the kubernetes service
func CreateKubeService(clientset *kubernetes.Clientset, namespace string, service *corev1.Service) (*corev1.Service, error) {
	return clientset.CoreV1().Services(namespace).Create(context.TODO(), service, metav1.CreateOptions{})
}

// UpdateService will update the service information for the input service name inside the input namespace
func UpdateService(clientset *kubernetes.Clientset, namespace string, service *corev1.Service) (*corev1.Service, error) {
	return clientset.CoreV1().Services(namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
}

// DeleteService will delete the service information for the input service name inside the input namespace
func DeleteService(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.CoreV1().Services(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetServiceEndPoint will get the service endpoint information for the input service name inside the input namespace
func GetServiceEndPoint(clientset *kubernetes.Clientset, namespace string, serviceName string) (*corev1.Endpoints, error) {
	return clientset.CoreV1().Endpoints(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
}

// ListStorageClasses will list all the storageClass in the cluster
func ListStorageClasses(clientset *kubernetes.Clientset) (*v1beta1.StorageClassList, error) {
	return clientset.StorageV1beta1().StorageClasses().List(context.TODO(), metav1.ListOptions{})
}

// GetPVC will get the PVC for the given name
func GetPVC(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.PersistentVolumeClaim, error) {
	return clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListPVCs will list the PVC for the given label selector
func ListPVCs(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.PersistentVolumeClaimList, error) {
	return clientset.CoreV1().PersistentVolumeClaims(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdatePVC will update the pvc information for the input pvc name inside the input namespace
func UpdatePVC(clientset *kubernetes.Clientset, namespace string, pvc *corev1.PersistentVolumeClaim) (*corev1.PersistentVolumeClaim, error) {
	return clientset.CoreV1().PersistentVolumeClaims(namespace).Update(context.TODO(), pvc, metav1.UpdateOptions{})
}

// DeletePVC will delete the PVC information for the input pvc name inside the input namespace
func DeletePVC(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.CoreV1().PersistentVolumeClaims(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetServiceAccount get a service account
func GetServiceAccount(clientset *kubernetes.Clientset, namespace string, name string) (*corev1.ServiceAccount, error) {
	return clientset.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListServiceAccounts list a service account
func ListServiceAccounts(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*corev1.ServiceAccountList, error) {
	return clientset.CoreV1().ServiceAccounts(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateServiceAccount updates a service account
func UpdateServiceAccount(clientset *kubernetes.Clientset, namespace string, serviceAccount *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
	return clientset.CoreV1().ServiceAccounts(namespace).Update(context.TODO(), serviceAccount, metav1.UpdateOptions{})
}

// DeleteServiceAccount delete a service account
func DeleteServiceAccount(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.CoreV1().ServiceAccounts(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetClusterRoleBinding get a cluster role
func GetClusterRoleBinding(clientset *kubernetes.Clientset, name string) (*rbacv1.ClusterRoleBinding, error) {
	return clientset.RbacV1().ClusterRoleBindings().Get(context.TODO(), name, metav1.GetOptions{})
}

// ListClusterRoleBindings list a cluster role binding
func ListClusterRoleBindings(clientset *kubernetes.Clientset, labelSelector string) (*rbacv1.ClusterRoleBindingList, error) {
	return clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateClusterRoleBinding updates the cluster role binding
func UpdateClusterRoleBinding(clientset *kubernetes.Clientset, clusterRoleBinding *rbacv1.ClusterRoleBinding) (*rbacv1.ClusterRoleBinding, error) {
	return clientset.RbacV1().ClusterRoleBindings().Update(context.TODO(), clusterRoleBinding, metav1.UpdateOptions{})
}

// DeleteClusterRoleBinding delete a cluster role binding
func DeleteClusterRoleBinding(clientset *kubernetes.Clientset, name string) error {
	return clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// IsClusterRoleBindingSubjectNamespaceExist checks whether the namespace is already exist in the subject of cluster role binding
func IsClusterRoleBindingSubjectNamespaceExist(subjects []rbacv1.Subject, namespace string) bool {
	for _, subject := range subjects {
		if strings.EqualFold(subject.Namespace, namespace) {
			return true
		}
	}
	return false
}

// IsClusterRoleRefExistForOtherNamespace checks whether the cluster role exist for any cluster role bindings present in other namespace
func IsClusterRoleRefExistForOtherNamespace(roleRef rbacv1.RoleRef, roleName string, namespace string, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		if "clusterrole" == strings.ToLower(roleRef.Kind) && strings.EqualFold(roleRef.Name, roleName) && !strings.EqualFold(namespace, subject.Namespace) {
			return true
		}
	}
	return false
}

// IsSubjectExistForOtherNamespace checks whether anyother namespace is exist in the subject of cluster role binding
func IsSubjectExistForOtherNamespace(subject rbacv1.Subject, namespace string) bool {
	if !strings.EqualFold(subject.Namespace, namespace) {
		return true
	}
	return false
}

// IsSubjectExist checks whether the namespace is already exist in the subject of cluster role binding
func IsSubjectExist(subjects []rbacv1.Subject, namespace string, name string) bool {
	for _, subject := range subjects {
		if strings.EqualFold(subject.Namespace, namespace) && strings.EqualFold(subject.Name, name) {
			return true
		}
	}
	return false
}

// GetClusterRole get a cluster role
func GetClusterRole(clientset *kubernetes.Clientset, name string) (*rbacv1.ClusterRole, error) {
	return clientset.RbacV1().ClusterRoles().Get(context.TODO(), name, metav1.GetOptions{})
}

// ListClusterRoles list a cluster role
func ListClusterRoles(clientset *kubernetes.Clientset, labelSelector string) (*rbacv1.ClusterRoleList, error) {
	return clientset.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateClusterRole updates the cluster role
func UpdateClusterRole(clientset *kubernetes.Clientset, clusterRole *rbacv1.ClusterRole) (*rbacv1.ClusterRole, error) {
	return clientset.RbacV1().ClusterRoles().Update(context.TODO(), clusterRole, metav1.UpdateOptions{})
}

// DeleteClusterRole delete a cluster role
func DeleteClusterRole(clientset *kubernetes.Clientset, name string) error {
	return clientset.RbacV1().ClusterRoles().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// IsClusterRoleRuleExist checks whether the namespace is already exist in the rule of cluster role
func IsClusterRoleRuleExist(oldRules []rbacv1.PolicyRule, newRule rbacv1.PolicyRule) bool {
	for _, oldRule := range oldRules {
		if reflect.DeepEqual(oldRule, newRule) {
			return true
		}
	}
	return false
}

// GetRole get a role
func GetRole(clientset *kubernetes.Clientset, namespace string, name string) (*rbacv1.Role, error) {
	return clientset.RbacV1().Roles(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListRoles list a role
func ListRoles(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*rbacv1.RoleList, error) {
	return clientset.RbacV1().Roles(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateRole updates the role
func UpdateRole(clientset *kubernetes.Clientset, namespace string, role *rbacv1.Role) (*rbacv1.Role, error) {
	return clientset.RbacV1().Roles(namespace).Update(context.TODO(), role, metav1.UpdateOptions{})
}

// DeleteRole delete a role
func DeleteRole(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.RbacV1().Roles(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetRoleBinding get a role binding
func GetRoleBinding(clientset *kubernetes.Clientset, namespace string, name string) (*rbacv1.RoleBinding, error) {
	return clientset.RbacV1().RoleBindings(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListRoleBindings list a role binding
func ListRoleBindings(clientset *kubernetes.Clientset, namespace string, labelSelector string) (*rbacv1.RoleBindingList, error) {
	return clientset.RbacV1().RoleBindings(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateRoleBinding updates the role binding
func UpdateRoleBinding(clientset *kubernetes.Clientset, namespace string, role *rbacv1.RoleBinding) (*rbacv1.RoleBinding, error) {
	return clientset.RbacV1().RoleBindings(namespace).Update(context.TODO(), role, metav1.UpdateOptions{})
}

// DeleteRoleBinding delete a role binding
func DeleteRoleBinding(clientset *kubernetes.Clientset, namespace string, name string) error {
	return clientset.RbacV1().RoleBindings(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetRouteClient attempts to get a Route Client. It returns nil if it
// fails due to an error or due to being on kubernetes (doesn't support routes)
func GetRouteClient(restConfig *rest.Config, clientset *kubernetes.Clientset, namespace string) *routeclient.RouteV1Client {
	routeClient, err := routeclient.NewForConfig(restConfig)
	if err != nil {
		return nil
	}
	return routeClient
}

// GetRoute gets an OpenShift routes
func GetRoute(routeClient *routeclient.RouteV1Client, namespace string, name string) (*routev1.Route, error) {
	return routeClient.Routes(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListRoutes list an OpenShift routes
func ListRoutes(routeClient *routeclient.RouteV1Client, namespace string, labelSelector string) (*routev1.RouteList, error) {
	return routeClient.Routes(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labelSelector})
}

// UpdateRoute updates an OpenShift routes
func UpdateRoute(routeClient *routeclient.RouteV1Client, namespace string, route *routev1.Route) (*routev1.Route, error) {
	return routeClient.Routes(namespace).Update(context.TODO(), route, metav1.UpdateOptions{})
}

// GetRouteComponent returns the route component
func GetRouteComponent(route *api.Route, labels map[string]string) *routev1.Route {
	componentRoute := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      route.Name,
			Namespace: route.Namespace,
			Labels:    labels,
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: route.Kind,
				Name: route.ServiceName,
			},
			Port: &routev1.RoutePort{TargetPort: intstr.IntOrString{Type: intstr.String, StrVal: route.PortName}},
		},
	}
	if len(route.TLSTerminationType) > 0 {
		componentRoute.Spec.TLS = &routev1.TLSConfig{Termination: route.TLSTerminationType}
	}
	return componentRoute
}

// CreateRoute creates an OpenShift routes
func CreateRoute(routeClient *routeclient.RouteV1Client, namespace string, route *routev1.Route) (*routev1.Route, error) {
	return routeClient.Routes(namespace).Create(context.TODO(), route, metav1.CreateOptions{})
}

// DeleteRoute deletes an OpenShift routes
func DeleteRoute(routeClient *routeclient.RouteV1Client, namespace string, name string) error {
	return routeClient.Routes(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetOpenShiftSecurityConstraint gets an OpenShift security constraints
func GetOpenShiftSecurityConstraint(osSecurityClient *securityclient.SecurityV1Client, name string) (*securityv1.SecurityContextConstraints, error) {
	return osSecurityClient.SecurityContextConstraints().Get(context.TODO(), name, metav1.GetOptions{})
}

// UpdateOpenShiftSecurityConstraint updates an OpenShift security constraints
func UpdateOpenShiftSecurityConstraint(osSecurityClient *securityclient.SecurityV1Client, serviceAccounts []string, name string) error {
	scc, err := GetOpenShiftSecurityConstraint(osSecurityClient, name)
	if err != nil {
		return fmt.Errorf("failed to get scc %s: %v", name, err)
	}

	newUsers := []string{}
	// Only add the service account if it isn't already in the list of users for the privileged scc
	for _, sa := range serviceAccounts {
		exist := false
		for _, user := range scc.Users {
			if strings.Compare(user, sa) == 0 {
				exist = true
				break
			}
		}

		if !exist {
			newUsers = append(newUsers, sa)
		}
	}

	if len(newUsers) > 0 {
		scc.Users = append(scc.Users, newUsers...)

		_, err = osSecurityClient.SecurityContextConstraints().Update(context.TODO(), scc, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update scc %s: %v", name, err)
		}
	}
	return err
}

// EnsureFilterPodsByNamePrefixInNamespaceToZero filters the pods based on the prefix and make sure that it is zero
func EnsureFilterPodsByNamePrefixInNamespaceToZero(clientset *kubernetes.Clientset, namespace string, prefix string) error {
	// timer starts the timer for timeoutInSeconds. If the task doesn't completed, return error
	timeout := time.NewTimer(120 * time.Second)
	// ticker starts and execute the task for every n intervals
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			pods, err := filterPodsByNamePrefixInNamespace(clientset, namespace, prefix)
			if err != nil {
				return err
			}

			if len(pods) == 0 {
				return nil
			}
			return fmt.Errorf("[WARNING] timeout expired to scale down the pod for replication controller %s in namespace %s", prefix, namespace)
		case <-ticker.C:
			pods, err := filterPodsByNamePrefixInNamespace(clientset, namespace, prefix)
			if err != nil {
				return err
			}

			if len(pods) == 0 {
				return nil
			}
		}
	}
}

// filterPodsByNamePrefixInNamespace will filter the pod based on pod name prefix from a list a pods in a given namespace
func filterPodsByNamePrefixInNamespace(clientset *kubernetes.Clientset, namespace string, prefix string) ([]*corev1.Pod, error) {
	pods, err := ListPods(clientset, namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to list the pods in namespace %s due to %+v", namespace, err)
	}

	pod := filterPodsByNamePrefix(pods, prefix)
	if len(pod) > 0 {
		return pod, nil
	}
	return nil, nil
}

// filterPodsByNamePrefix will filter the pod based on pod name prefix from a list a pods
func filterPodsByNamePrefix(pods *corev1.PodList, prefix string) []*corev1.Pod {
	podsArr := make([]*corev1.Pod, 0)
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, prefix) && pod.Status.Phase != corev1.PodFailed && pod.Status.Phase != corev1.PodUnknown {
			podsArr = append(podsArr, &pod)
		}
	}
	return podsArr
}

// GetKubernetesVersion will return the kubernetes version
func GetKubernetesVersion(clientset *kubernetes.Clientset) (string, error) {
	k, err := clientset.Discovery().ServerVersion()
	if k != nil {
		return k.GitVersion, nil
	}
	return "", err
}

// IsOpenshift will whether it is an openshift cluster
func IsOpenshift(clientset *kubernetes.Clientset) bool {
	body, err := clientset.Discovery().RESTClient().Get().AbsPath("/").Do(context.TODO()).Raw()
	if err != nil {
		return false
	}

	return strings.Contains(string(body), "openshift")
}

// InitLabels initialize the label
func InitLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return make(map[string]string, 0)
	}
	return labels
}

// InitAnnotations initialize the annotation
func InitAnnotations(annotations map[string]string) map[string]string {
	if annotations == nil {
		return make(map[string]string, 0)
	}
	return annotations
}
