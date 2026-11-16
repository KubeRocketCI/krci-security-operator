# krci-security-operator

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

A Helm chart for the KubeRocketCI Security Operator

**Homepage:** <https://docs.kuberocketci.io/>

## Introduction

KubeRocketCI Security Operator runs the security integrations of a cluster, one module per integration.
The first module imports Trivy Operator reports (`VulnerabilityReport`, `ExposedSecretReport`) into the DefectDojo of the cluster.
One instance runs per cluster with cluster-wide read-only access and writes only to DefectDojo.

## Prerequisites

- [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) is installed in the cluster and produces the reports.
- DefectDojo is reachable from the operator pod.
- A Secret in the release namespace holds the DefectDojo address and API token under the keys `url` and `token`. Its name is set in `defectdojo.secretName`:

  ```bash
  kubectl create secret generic defectdojo-credentials -n <namespace> \
    --from-literal=url=https://defectdojo.example.com \
    --from-literal=token=<api-token>
  ```

## Deploy with Helm

1. Add the Helm EPAMEDP Charts repository:

    ```bash
    helm repo add epamedp https://epam.github.io/edp-helm-charts/stable
    ```

2. Choose an available chart version:

    ```bash
    helm search repo epamedp/krci-security-operator -l
    ```

    _**NOTE:** It is highly recommended to use the latest released version._

3. Install the operator:

    ```bash
    helm install krci-security-operator epamedp/krci-security-operator --version <chart_version> -n <namespace>
    ```

4. Check that the pod of the operator is running.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| epmd-edp | <SupportEPMD-EDP@epam.com> | <https://solutionshub.epam.com/solution/kuberocketci> |

## Source Code

* <https://github.com/KubeRocketCI/krci-security-operator>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity for pod assignment |
| annotations | object | `{}` | Annotations to add to the deployment |
| clusterName | string | `"in-cluster"` | Cluster name. Every imported test carries the tag `krci-cluster:<clusterName>`, and the operator closes only the tests that carry it |
| componentPrefixes | list | `["in-cluster-"]` | Prefixes stripped from the Argo CD application name when the component tag is derived |
| concurrency | int | `2` | Number of namespaces reconciled in parallel |
| defectdojo.platformProduct | string | `"platform"` | DefectDojo product of the platform scope |
| defectdojo.productType | string | `"KubeRocketCI"` | DefectDojo product type of the products the operator creates |
| defectdojo.secretName | string | `"defectdojo-credentials"` | Secret in the release namespace with the keys `url` and `token` of the cluster's DefectDojo. The operator reads it at runtime and never writes it |
| excludeNamespaces | list | `[]` | Glob patterns of namespaces that are skipped |
| extraVolumeMounts | list | `[]` | Additional volume mounts to add to the manager container |
| extraVolumes | list | `[]` | Additional volumes to add to the manager pod |
| image.registry | string | `""` | krci-security-operator image registry. Leave empty to use the repository as-is (Docker Hub by default) |
| image.repository | string | `"epamedp/krci-security-operator"` | krci-security-operator Docker image name. The released image can be found on [Dockerhub](https://hub.docker.com/r/epamedp/krci-security-operator) |
| image.tag | string | `nil` | krci-security-operator Docker image tag. The released image can be found on [Dockerhub](https://hub.docker.com/r/epamedp/krci-security-operator). If not defined then .Chart.AppVersion is used |
| imagePullPolicy | string | `"IfNotPresent"` | Image pull policy |
| imagePullSecrets | list | `[]` | Optional array of imagePullSecrets containing private registry credentials # Ref: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry |
| name | string | `"krci-security-operator"` | component name |
| nodeSelector | object | `{}` | Node labels for pod assignment |
| podSecurityContext | object | `{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level security context # Ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ |
| reportKinds | list | `["VulnerabilityReport","ExposedSecretReport"]` | Trivy Operator report kinds to import. Supported: `VulnerabilityReport`, `ExposedSecretReport` |
| resources | object | `{"limits":{"memory":"512Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Resource requests/limits for the manager container. Memory scales with `concurrency` multiplied by one page of 10 full Trivy reports (a report can reach 3 MB), plus the metadata of all reports in the cluster: raise the memory limit when `concurrency` or the report sizes grow. # Ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| resyncPeriod | string | `"30m"` | Interval of the periodic re-check of every namespace (Go duration) |
| scopes.platform | bool | `true` | Import the reports of the remaining (platform) namespaces |
| scopes.stage | bool | `true` | Import the reports of namespaces that belong to a Stage |
| scopes.tenant | bool | `true` | Import the reports of tenant namespaces (label `app.edp.epam.com/tenant`) that belong to no Stage |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container-level security context # Ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ |
| tolerations | list | `[]` | Tolerations for pod assignment |
