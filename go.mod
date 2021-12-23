module github.com/blackducksoftware/synopsysctl

go 1.16

require (
	github.com/blackducksoftware/horizon v0.0.0-20190625151958-16cafa9109a3
	github.com/containerd/containerd v1.4.12 // indirect
	github.com/ghodss/yaml v1.0.0
	github.com/imdario/mergo v0.3.12
	github.com/juju/errors v0.0.0-20210818161939-5560c4c073ff
	github.com/mitchellh/go-homedir v1.1.0
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/openshift/api v0.0.0-20200217161739-c99157bc6492
	github.com/openshift/client-go v0.0.0-20200116152001-92a2713fa240
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.3.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.0
	gotest.tools/v3 v3.0.3 // indirect
	helm.sh/helm/v3 v3.1.3
	k8s.io/api v0.18.8
	k8s.io/apiextensions-apiserver v0.18.8
	k8s.io/apimachinery v0.18.8
	k8s.io/cli-runtime v0.18.8
	k8s.io/client-go v0.18.8
	k8s.io/klog v1.0.0
	rsc.io/letsencrypt v0.0.3 // indirect
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v14.2.0+incompatible
	github.com/Azure/go-autorest/autorest/adal => github.com/Azure/go-autorest/autorest/adal v0.8.2
	github.com/containerd/containerd => github.com/containerd/containerd v1.4.12
	github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.2
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.3
	helm.sh/helm/v3 => helm.sh/helm/v3 v3.1.3
	k8s.io/api => k8s.io/api v0.17.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.17.3
	k8s.io/client-go => k8s.io/client-go v0.17.3
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
