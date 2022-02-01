package testutils

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	// get auth clients for gcp
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// KubeConfigPath ...
var KubeConfigPath string

// Restconfig ...
var Restconfig *rest.Config

// KubeClient ...
var KubeClient *kubernetes.Clientset

// SetUpClusterClients ...
func SetUpClusterClients() error {
	var err error
	KubeConfigPath, err = getGlobalKubeConfigPath()
	if err != nil {
		log.Fatalf("%+v", err)
		return fmt.Errorf("%+v", err)
	}
	Restconfig, err = GetKubeConfig(KubeConfigPath, false)
	if err != nil {
		log.Fatalf("%+v", err)
		return fmt.Errorf("%+v", err)
	}
	KubeClient, err = getKubeClient(Restconfig)
	if err != nil {
		log.Fatalf("%+v", err)
		return fmt.Errorf("%+v", err)
	}
	return nil
}

// getKubeClient gets the kubernetes client
func getKubeClient(kubeConfig *rest.Config) (*kubernetes.Clientset, error) {
	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	log.Infof("Set Kube Client with Rest Config")
	return client, nil
}

func getGlobalKubeConfigPath() (string, error) {
	var path string
	if kubeconfigEnvVal, exists := os.LookupEnv("KUBECONFIG"); exists { // set kubeconfig if environ is set
		path = kubeconfigEnvVal
	}
	// if the path was set, verify that the file exists
	if path != "" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return "", fmt.Errorf("the kubeconfig path '%s' does not point to a file", path)
		}
	}
	log.Infof("Kube Config Path: '%+v'", path)
	return path, nil
}

// GetKubeConfig returns a kubeconfig for inside or outside the cluster
func GetKubeConfig(kubeconfigpath string, insecureSkipTLSVerify bool) (*rest.Config, error) {
	var err error
	var kubeConfig *rest.Config
	// creates the in-cluster config
	kubeConfig, err = rest.InClusterConfig()
	if err != nil {
		kubeConfig, err = GetKubeClientFromOutsideCluster(kubeconfigpath, insecureSkipTLSVerify)
		if err != nil {
			return nil, err
		}
		log.Infof("Getting Rest Config for Outside Cluster")
		return kubeConfig, nil
	}
	log.Infof("Getting Rest Config for Inside Cluster")
	return kubeConfig, nil
}

// GetKubeClientFromOutsideCluster returns the rest config of outside cluster
func GetKubeClientFromOutsideCluster(kubeconfigpath string, insecureSkipTLSVerify bool) (*rest.Config, error) {
	// Determine Config Paths
	if home := homeDir(); len(kubeconfigpath) == 0 && home != "" {
		kubeconfigpath = filepath.Join(home, ".kube", "config")
	}

	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{
			ExplicitPath: kubeconfigpath,
		},
		&clientcmd.ConfigOverrides{
			ClusterInfo: clientcmdapi.Cluster{
				Server:                "",
				InsecureSkipTLSVerify: insecureSkipTLSVerify,
			},
		}).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubeConfig, nil
}

// homeDir determines the user's home directory path
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
