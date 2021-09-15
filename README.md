# synopsysctl
Cloud native tool to deploy Synopsys applications in Kubernetes and OpenShift

## Versioning Format: SemVer

Synopsysctl follows SemVer versioning ( **major** . **minor** . **patch** )  

**major**: Changes to the interface  
* New flags or commands
* Support for new products

**minor**: Changes that can be supported by the current major version
* Product uses Deployments instead of ReplicationControllers; Environs are stored in different Secrets; etc.

**patch**: Bug fixes  
* Clean up a bad error message
* Fixing bug in product functionality

## Quickstart

Prereqs: assuming you have tls.crt and tls.key files, just run:

```
NS=bd
kubectl create ns $NS

cd cmd/synopsysctl

SEAL_KEY=01234567890123456789012345678901
ADMIN_PASSWORD=abc123
USER_PASSWORD=qrstuv

go run main.go create blackduck $NS \
  --namespace $NS \
  --expose-ui loadbalancer \
  --admin-password $ADMIN_PASSWORD \
  --user-password $USER_PASSWORD \
  --seal-key $SEAL_KEY \
  --certificate-file-path tls.crt \
  --certificate-key-file-path tls.key \
  --verbose-level trace \
  --size small
```

This will take a few minutes, so please be patient and watch `kubectl get pods -A`!

### Using Blackduck

*Option 1*: port-forwarding

```
# kubectl get pods -n bd
# choose the webserver pod
kubectl -n bd port-forward bd-blackduck-webserver-7fdd87854c-chqjv 1111:8443

# go to https://localhost:1111 in your web browser
```

*Option 2*: expose a service

```
kubectl expose svc -n bd bd-blackduck-webserver --type LoadBalancer --name webserver-exposed-443-8443 --port 443 --target-port 8443

# access the external-ip at https://EXTERNAL_IP
kubectl get svc -n bd webserver-exposed-443-8443
```

### Upgrade to 2021.8.1 and above using native command
For customers using native command to deploy Black Duck, when upgrading Black Duck from version 2021.6.x to version 2021.8.1 and above, you must delete the webui service before performing a helm upgrade. This can be done by running the following commands:
```
kubectl -n <namespace> delete deployment <namespace>-blackduck-webui
kubectl -n <namespace> delete service <namespace>-blackduck-webui
```