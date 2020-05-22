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