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

package util

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// WaitForPodsToBeDeletedOrComplete ...
func WaitForPodsToBeDeletedOrComplete(kubeClient *kubernetes.Clientset, namespace string, labelSelector string) error {
	timeout := time.NewTimer(5 * time.Minute) // fail after 5 minutes
	ticker := time.NewTicker(5 * time.Second) // check every 5 seconds
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("pods failed to stop or complete in namespace '%s'", namespace)
		case <-ticker.C:
			pods, err := ListPodsWithLabels(kubeClient, namespace, labelSelector)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			// Break if there are no pods or if all jobs are Succeeded
			if len(pods.Items) == 0 {
				return nil
			}
			podsAreAllSucceeded := true
			for _, po := range pods.Items {
				if po.Status.Phase != corev1.PodSucceeded {
					podsAreAllSucceeded = false
					break
				}
			}
			if podsAreAllSucceeded {
				return nil
			}
		}
	}
}

// WaitForPodsToBeRunningOrComplete ...
func WaitForPodsToBeRunningOrComplete(kubeClient *kubernetes.Clientset, namespace string, labelSelector string) error {
	timeout := time.NewTimer(5 * time.Minute) // fail after 5 minutes
	ticker := time.NewTicker(5 * time.Second) // check every 5 seconds
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("pods failed to start or complete in namespace '%s'", namespace)
		case <-ticker.C:
			pods, err := ListPodsWithLabels(kubeClient, namespace, labelSelector)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			// Check if all pods are running or succeeded
			podsAreAllStartedOrSucceeded := true
			for _, po := range pods.Items {
				podIsRunning := PodIsRunningOrComplete(po)
				if !podIsRunning || !PodContainersAreRunning(po) {
					podsAreAllStartedOrSucceeded = false
					break
				}
			}
			if podsAreAllStartedOrSucceeded {
				return nil
			}
		}
	}
}

// WaitForPodsToStartChanging ...
// TODO - need to test if this function works
func WaitForPodsToStartChanging(kubeClient *kubernetes.Clientset, namespace string, labelSelector string) error {
	timeout := time.NewTimer(1 * time.Minute) // fail after 1 minute
	ticker := time.NewTicker(1 * time.Second) // check every 1 second
	defer ticker.Stop()
	defer timeout.Stop()

	startingPodsMap := map[string]corev1.Pod{}
	pods, err := ListPodsWithLabels(kubeClient, namespace, labelSelector)
	if err != nil {
		return errors.Wrap(err, "failed to list pods")
	}
	for _, po := range pods.Items {
		startingPodsMap[po.Name] = po
	}

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("pods failed to start changing in namespace '%s'", namespace)
		case <-ticker.C:
			pods, err := ListPodsWithLabels(kubeClient, namespace, labelSelector)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			for _, po := range pods.Items {
				if _, ok := startingPodsMap[po.Name]; !ok {
					return nil // Pod Name is not in starting Pods, thus they started changing
				}
			}
		}
	}
}

// WaitForPodsToStopTerminating ...
func WaitForPodsToStopTerminating(kubeClient *kubernetes.Clientset, namespace string) error {
	timeout := time.NewTimer(2 * time.Minute) // fail after 2 minutes
	ticker := time.NewTicker(1 * time.Second) // check every 1 second
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("pods failed to stop terminating namespace '%s'", namespace)
		case <-ticker.C:
			pods, err := ListPods(kubeClient, namespace)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			// Check if any pods are terminating
			podsAreNotTerminating := true
			for _, po := range pods.Items {
				if PodIsTerminating(po) {
					podsAreNotTerminating = false
					break
				}
			}
			if podsAreNotTerminating {
				return nil
			}
		}
	}
}

// PodIsRunningOrComplete ...
func PodIsRunningOrComplete(pod corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodRunning {
		return false
	}
	return true
}

// PodContainersAreRunning ...
func PodContainersAreRunning(pod corev1.Pod) bool {
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running == nil {
			return false
		}
	}
	return true
}

// PodIsTerminating ...
func PodIsTerminating(pod corev1.Pod) bool {
	if pod.ObjectMeta.DeletionTimestamp != nil {
		return true
	}
	return false
}

// WaitForPodsToAppear ...
func WaitForPodsToAppear(kubeClient *kubernetes.Clientset, namespace string, labelSelector string) error {
	timeout := time.NewTimer(1 * time.Minute) // fail after 1 minute
	ticker := time.NewTicker(1 * time.Second) // check every 1 second
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("pods failed to appear '%s'", namespace)
		case <-ticker.C:
			pods, err := ListPodsWithLabels(kubeClient, namespace, labelSelector)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			if len(pods.Items) > 0 {
				return nil
			}
		}
	}
}

// WaitForMoreThanNPods ...
func WaitForMoreThanNPods(kubeClient *kubernetes.Clientset, namespace string, labelSelector string, n int) error {
	timeout := time.NewTimer(2 * time.Minute) // fail after 2 minutes
	ticker := time.NewTicker(1 * time.Second) // check every 1 second
	defer ticker.Stop()
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("failed to be more than %d pods in namespace '%s'", n, namespace)
		case <-ticker.C:
			pods, err := ListPods(kubeClient, namespace)
			if err != nil {
				return errors.Wrap(err, "failed to list pods")
			}
			if len(pods.Items) > n {
				return nil
			}
		}
	}
}
