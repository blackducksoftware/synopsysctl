module github.com/blackducksoftware/synopsysctl

go 1.13

require (
	github.com/blackducksoftware/horizon v0.0.0-20190625151958-16cafa9109a3
	github.com/ghodss/yaml v1.0.0
	github.com/imdario/mergo v0.3.7
	github.com/juju/errors v0.0.0-20190806202954-0232dcc7464d
	github.com/juju/loggo v0.0.0-20190526231331-6e530bcce5d8 // indirect
	github.com/juju/testing v0.0.0-20191001232224-ce9dec17d28b // indirect
	github.com/mattn/go-isatty v0.0.7 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/onsi/ginkgo v1.10.3 // indirect
	github.com/onsi/gomega v1.7.1 // indirect
	github.com/openshift/api v0.0.0-20200217161739-c99157bc6492
	github.com/openshift/client-go v0.0.0-20200116152001-92a2713fa240
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.6.2
	github.com/stretchr/testify v1.4.0
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	helm.sh/helm/v3 v3.1.1
	k8s.io/api v0.17.3
	k8s.io/apiextensions-apiserver v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/cli-runtime v0.17.3
	k8s.io/client-go v0.17.3
	k8s.io/klog v1.0.0
	rsc.io/letsencrypt v0.0.3 // indirect
	sigs.k8s.io/yaml v1.1.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.3+incompatible
	github.com/Azure/go-autorest/autorest/adal => github.com/Azure/go-autorest/autorest/adal v0.8.2
	github.com/blackducksoftware/horizon => github.com/blackducksoftware/horizon v0.0.0-20190625151958-16cafa9109a3
	github.com/docker/spdystream => github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c // indirect
	github.com/evanphx/json-patch => github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.4.0
	github.com/golang/mock => github.com/golang/mock v1.2.0 // indirect
	github.com/google/go-cmp => github.com/google/go-cmp v0.3.0
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.3.0 // indirect
	github.com/gophercloud/gophercloud => github.com/gophercloud/gophercloud v0.3.0 // indirect
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.7
	github.com/juju/errors => github.com/juju/errors v0.0.0-20190806202954-0232dcc7464d
	github.com/lib/pq => github.com/lib/pq v1.2.0
	github.com/mitchellh/go-homedir => github.com/mitchellh/go-homedir v1.1.0
	github.com/onsi/ginkgo => github.com/onsi/ginkgo v1.7.0
	github.com/onsi/gomega => github.com/onsi/gomega v1.4.3
	github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.3
	github.com/spf13/viper => github.com/spf13/viper v1.4.0
	github.com/stretchr/testify => github.com/stretchr/testify v1.3.0
	gopkg.in/inf.v0 => gopkg.in/inf.v0 v0.9.1 // indirect
	helm.sh/helm/v3 => helm.sh/helm/v3 v3.1.1
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)
