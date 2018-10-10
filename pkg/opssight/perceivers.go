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

package opssight

import (
	"encoding/json"
	"fmt"

	horizonapi "github.com/blackducksoftware/horizon/pkg/api"
	"github.com/blackducksoftware/horizon/pkg/components"
	"github.com/juju/errors"
)

// PodPerceiverReplicationController creates a replication controller for the pod perceiver
func (p *SpecConfig) PodPerceiverReplicationController() (*components.ReplicationController, error) {
	name := p.config.Names.PodPerceiver
	rc := p.perceiverReplicationController(name, 1)

	pod, err := p.perceiverPod(name, p.config.ServiceAccounts["pod-perceiver"])
	if err != nil {
		return nil, fmt.Errorf("failed to create pod perceiver pod: %v", err)
	}
	rc.AddPod(pod)

	return rc, nil
}

// ImagePerceiverReplicationController creates a replication controller for the image perceiver
func (p *SpecConfig) ImagePerceiverReplicationController() (*components.ReplicationController, error) {
	name := p.config.Names.ImagePerceiver
	rc := p.perceiverReplicationController(name, 1)

	pod, err := p.perceiverPod(name, p.config.ServiceAccounts["image-perceiver"])
	if err != nil {
		return nil, fmt.Errorf("failed to create image perceiver pod: %v", err)
	}
	rc.AddPod(pod)

	return rc, nil
}

func (p *SpecConfig) perceiverReplicationController(name string, replicas int32) *components.ReplicationController {
	rc := components.NewReplicationController(horizonapi.ReplicationControllerConfig{
		Replicas:  &replicas,
		Name:      name,
		Namespace: p.config.Namespace,
	})
	rc.AddLabelSelectors(map[string]string{"name": name})

	return rc
}

func (p *SpecConfig) perceiverPod(name string, account string) (*components.Pod, error) {
	pod := components.NewPod(horizonapi.PodConfig{
		Name:           name,
		ServiceAccount: account,
	})

	pod.AddLabels(map[string]string{"name": name})
	pod.AddContainer(p.perceiverContainer(name))

	vols, err := perceiverVolumes(name)

	if err != nil {
		return nil, err
	}

	for _, v := range vols {
		pod.AddVolume(v)
	}

	return pod, nil
}

func (p *SpecConfig) perceiverContainer(name string) *components.Container {
	cmd := fmt.Sprintf("./%s", name)
	container := components.NewContainer(horizonapi.ContainerConfig{
		Name:    name,
		Image:   p.config.PodPerceiverImage,
		Command: []string{cmd},
		Args:    []string{fmt.Sprintf("/etc/%s/%s.yaml", name, name)},
		MinCPU:  p.config.DefaultCPU,
		MinMem:  p.config.DefaultMem,
	})

	container.AddPort(horizonapi.PortConfig{
		ContainerPort: fmt.Sprintf("%d", *p.config.PerceiverPort),
		Protocol:      horizonapi.ProtocolTCP,
	})

	container.AddVolumeMount(horizonapi.VolumeMountConfig{
		Name:      name,
		MountPath: fmt.Sprintf("/etc/%s", name),
	})
	container.AddVolumeMount(horizonapi.VolumeMountConfig{
		Name:      "logs",
		MountPath: "/tmp",
	})

	return container
}

func perceiverVolumes(name string) ([]*components.Volume, error) {
	vols := []*components.Volume{}

	vols = append(vols, components.NewConfigMapVolume(horizonapi.ConfigMapOrSecretVolumeConfig{
		VolumeName:      name,
		MapOrSecretName: name,
	}))

	vol, err := components.NewEmptyDirVolume(horizonapi.EmptyDirVolumeConfig{
		VolumeName: "logs",
		Medium:     horizonapi.StorageMediumDefault,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create empty dir volume: %v", err)
	}
	vols = append(vols, vol)

	return vols, nil
}

func (p *SpecConfig) perceiverService(name string) *components.Service {
	service := components.NewService(horizonapi.ServiceConfig{
		Name:      name,
		Namespace: p.config.Namespace,
	})

	service.AddPort(horizonapi.ServicePortConfig{
		Port:       int32(*p.config.PerceiverPort),
		TargetPort: fmt.Sprintf("%d", *p.config.PerceiverPort),
		Protocol:   horizonapi.ProtocolTCP,
	})

	service.AddSelectors(map[string]string{"name": name})

	return service
}

// PodPerceiverService creates a service for the pod perceiver
func (p *SpecConfig) PodPerceiverService() *components.Service {
	return p.perceiverService(p.config.Names.PodPerceiver)
}

// ImagePerceiverService creates a service for the image perceiver
func (p *SpecConfig) ImagePerceiverService() *components.Service {
	return p.perceiverService(p.config.Names.ImagePerceiver)
}

// PerceiverConfigMap creates a config map for perceivers
func (p *SpecConfig) PerceiverConfigMap(name string) (*components.ConfigMap, error) {
	configMap := components.NewConfigMap(horizonapi.ConfigMapConfig{
		Name:      name,
		Namespace: p.config.Namespace,
	})

	data := map[string]interface{}{
		"PerceptorHost":             p.config.Names.Perceptor,
		"PerceptorPort":             *p.config.PerceptorPort,
		"AnnotationIntervalSeconds": *p.config.AnnotationIntervalSeconds,
		"DumpIntervalMinutes":       *p.config.DumpIntervalMinutes,
		"Port":                      *p.config.PerceiverPort,
		"LogLevel":                  p.config.LogLevel,
		"NamespaceFilter":           p.config.NamespaceFilter,
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, errors.Trace(err)
	}
	configMap.AddData(map[string]string{fmt.Sprintf("%s.yaml", name): string(bytes)})

	return configMap, nil
}

func (p *SpecConfig) perceiverServiceAccount(name string) *components.ServiceAccount {
	serviceAccount := components.NewServiceAccount(horizonapi.ServiceAccountConfig{
		Name:      name,
		Namespace: p.config.Namespace,
	})

	return serviceAccount
}

// PodPerceiverServiceAccount creates a service account for the pod perceiver
func (p *SpecConfig) PodPerceiverServiceAccount() *components.ServiceAccount {
	return p.perceiverServiceAccount(p.config.ServiceAccounts["pod-perceiver"])
}

// ImagePerceiverServiceAccount creates a service account for the image perceiver
func (p *SpecConfig) ImagePerceiverServiceAccount() *components.ServiceAccount {
	return p.perceiverServiceAccount(p.config.ServiceAccounts["image-perceiver"])
}

// PodPerceiverClusterRole creates a cluster role for the pod perceiver
func (p *SpecConfig) PodPerceiverClusterRole() *components.ClusterRole {
	clusterRole := components.NewClusterRole(horizonapi.ClusterRoleConfig{
		Name:       p.config.Names.PodPerceiver,
		APIVersion: "rbac.authorization.k8s.io/v1",
	})
	clusterRole.AddPolicyRule(horizonapi.PolicyRuleConfig{
		APIGroups: []string{"*"},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "watch", "list", "update"},
	})

	return clusterRole
}

// ImagePerceiverClusterRole creates a cluster role for the image perceiver
func (p *SpecConfig) ImagePerceiverClusterRole() *components.ClusterRole {
	clusterRole := components.NewClusterRole(horizonapi.ClusterRoleConfig{
		Name:       p.config.Names.ImagePerceiver,
		APIVersion: "rbac.authorization.k8s.io/v1",
	})
	clusterRole.AddPolicyRule(horizonapi.PolicyRuleConfig{
		APIGroups: []string{"*"},
		Resources: []string{"images"},
		Verbs:     []string{"get", "watch", "list", "update"},
	})

	return clusterRole
}

// PodPerceiverClusterRoleBinding creates a cluster role binding for the pod perceiver
func (p *SpecConfig) PodPerceiverClusterRoleBinding(clusterRole *components.ClusterRole) *components.ClusterRoleBinding {
	clusterRoleBinding := components.NewClusterRoleBinding(horizonapi.ClusterRoleBindingConfig{
		Name:       p.config.Names.PodPerceiver,
		APIVersion: "rbac.authorization.k8s.io/v1",
	})
	clusterRoleBinding.AddSubject(horizonapi.SubjectConfig{
		Kind:      "ServiceAccount",
		Name:      p.config.ServiceAccounts["pod-perceiver"],
		Namespace: p.config.Namespace,
	})
	clusterRoleBinding.AddRoleRef(horizonapi.RoleRefConfig{
		APIGroup: "",
		Kind:     "ClusterRole",
		Name:     clusterRole.GetName(),
	})

	return clusterRoleBinding
}

// ImagePerceiverClusterRoleBinding creates a cluster role binding for the image perceiver
func (p *SpecConfig) ImagePerceiverClusterRoleBinding(clusterRole *components.ClusterRole) *components.ClusterRoleBinding {
	clusterRoleBinding := components.NewClusterRoleBinding(horizonapi.ClusterRoleBindingConfig{
		Name:       p.config.Names.ImagePerceiver,
		APIVersion: "rbac.authorization.k8s.io/v1",
	})
	clusterRoleBinding.AddSubject(horizonapi.SubjectConfig{
		Kind:      "ServiceAccount",
		Name:      p.config.ServiceAccounts["image-perceiver"],
		Namespace: p.config.Namespace,
	})
	clusterRoleBinding.AddRoleRef(horizonapi.RoleRefConfig{
		APIGroup: "",
		Kind:     "ClusterRole",
		Name:     clusterRole.GetName(),
	})

	return clusterRoleBinding
}
