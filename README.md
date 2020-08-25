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
  --expose-ui nodeport \
  --admin-password $ADMIN_PASSWORD \
  --user-password $USER_PASSWORD \
  --seal-key $SEAL_KEY \
  --certificate-file-path tls.crt \
  --certificate-key-file-path tls.key \
  --verbose-level trace
```

This will take a few minutes, so please be patient and watch `kubectl get pods -A`!
