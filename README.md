# KubeRocketCI Security Operator

[![CI](https://github.com/KubeRocketCI/krci-security-operator/actions/workflows/pr.yaml/badge.svg)](https://github.com/KubeRocketCI/krci-security-operator/actions/workflows/pr.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/KubeRocketCI/krci-security-operator.svg)](https://pkg.go.dev/github.com/KubeRocketCI/krci-security-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The home for the in-house security integrations of a [KubeRocketCI](https://docs.kuberocketci.io) cluster. Each integration is a module of one operator that runs once per cluster, reads the cluster state, and writes only to the external security system.

The first module imports [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) reports into the cluster's [DefectDojo](https://www.defectdojo.org/). The operator defines no CRDs and no webhooks.

## How it works

The unit of work is a namespace. The operator reconciles a namespace when a `VulnerabilityReport` or `ExposedSecretReport` in it changes, when the namespace or a KubeRocketCI `Stage` that points at it changes, and every `resyncPeriod`.

1. **Classify** the namespace, on every pass:
   - **stage**: a `Stage` in any namespace has `spec.namespace` equal to the namespace, its `cdPipeline`, `name` and `namespace` are RFC 1123 DNS labels, and the namespace carries the label `app.edp.epam.com/tenant` equal to the Stage's namespace. When several Stages match, the first by Stage namespace and name wins and the others are logged.
   - **tenant**: the namespace has a non-empty `app.edp.epam.com/tenant` label and no Stage matches.
   - **platform**: everything else, including the KubeRocketCI install namespace when it has no tenant label.
2. **Skip** namespaces that match `excludeNamespaces` or belong to a scope that is switched off.
3. **Import**: list the namespace's reports, resolve each to its stable workload (a ReplicaSet to its Deployment, a Job to its CronJob; a StatefulSet, DaemonSet or Pod is its own workload), and re-import only the reports whose UID or resourceVersion changed since the last import. The state is in memory, so a restart re-imports once. Imports into one test are serialized.
4. **Close**, after each pass over an in-scope namespace, the owned tests tagged `krci-namespace:<ns>` that the pass did not import. That covers removed workloads and a namespace that changed its scope, for example from tenant to stage. The findings of other services in a test are closed once per test. A namespace that is gone or out of scope has all its owned tests closed, once.
5. **Sweep**: at start and every 6 hours, find the namespaces that own owned tests although the namespace no longer exists or is out of scope, and hand them to the controller. The sweeper closes nothing itself: the controller does, so all closing of a namespace is serialized with its imports.

### Errors, requeues and API load

- A transient failure (a Kubernetes read, a DefectDojo call, closing a test) is returned from the reconcile, so the workqueue backs off exponentially (30 seconds up to 10 minutes) and `controller_runtime_reconcile_errors_total` counts it.
- DefectDojo calls: a re-import is never retried after a timeout, a transport error or a 5xx, because DefectDojo may still be processing it and a second import into the same test duplicates findings; only a 429 is retried. Reads and the finding close call, which is idempotent, are retried with backoff. A re-import may take 10 minutes, every other call 2 minutes. The manager never stops for it.
- An absent optional dependency is not an error: while the credentials Secret is missing or has no `url` or `token`, or a report CRD is not served, the namespace is requeued after at most 5 minutes. The missing Secret is logged once per process at Info and then at debug level.
- A report that DefectDojo rejects with a client error (4xx) is permanent for that version: the version (UID and `resourceVersion`) is remembered and not uploaded again until the report changes. It does not fail the pass, so stale tests are still closed, and an earlier import of the same workload stays open. Each newly rejected version is logged at Error once and counted in the metric `krci_security_operator_rejected_reports_total{kind}`.
- Every namespace is requeued every `resyncPeriod`, spread by up to 10% either way.
- The credentials Secret is read at most once per minute. Report events that change no `resourceVersion` (informer resyncs) are dropped.
- Report and Stage kinds are discovered at start. A CRD installed later needs an operator restart to be watched; its namespaces still catch up on the next resync.

### Sizing

Reports are listed 10 at a time (`reportsPageSize` in `internal/controller/trivy/reconciler.go`). Each page is resolved and imported before the next is read, a report is released as soon as it is imported, and the payload shares the report body instead of copying it, so only the small sets of live tests and kept-open titles are kept across pages. The peak per reconcile is one page of reports plus the marshalled payload of one report. The memory of the manager scales with `concurrency` multiplied by that peak (a report can reach 3 MB, so a page is up to 30 MB), plus the metadata of all reports in the cluster. The chart defaults are a 128Mi request and a 512Mi limit; raise the limit when `concurrency` or the report sizes grow.

### Watches and reads

- The controller watches the metadata of `VulnerabilityReport` and `ExposedSecretReport` only (`metav1.PartialObjectMetadata`), because a report can reach 3 MB. Each event enqueues the namespace of the report.
- It also watches Namespaces (creation, deletion, label changes) and `Stage` objects. A Stage event enqueues `spec.namespace`, and for an update the previous value too.
- Everything else is read without a cache, through the API reader: the full reports of a namespace, ReplicaSets, Jobs, the labels and annotations of the top workload, `CodebaseImageStream`s and the credentials Secret.

The tenant of a namespace is its `app.edp.epam.com/tenant` label, never what a Stage claims: a Stage that points at a namespace labeled for another tenant does not make it a stage namespace. A deleting Stage still counts until it is gone. A scope switch takes effect on the next pass: the reports are imported under the new names and the tests of the old names are closed.

### DefectDojo naming

| Scope | Product | Engagement | Test title | Tags |
|---|---|---|---|---|
| stage | the codebase (via `CodebaseImageStream` in the tenant namespace), else `env:<cdPipeline>-<stage>` | `runtime:<cdPipeline>-<stage>` | `<ReportKind> <ns>/<kind>/<name>/<container>` | `krci-scope:runtime`, `krci-tenant:<tenant>`, `krci-env:<cdp>.<stage>`, `krci-codebase:<cb>` when mapped |
| tenant | `tenant:<tenant>` | `namespace:<ns>` | same | `krci-scope:tenant`, `krci-tenant:<tenant>` |
| platform | `platform` (configurable) | `namespace:<ns>` | same | `krci-scope:platform` |

- Every test also carries `krci-namespace:<ns>`, `krci-workload:<kind>.<name>`, `krci-container:<c>`, `krci-component:<component>` and `krci-cluster:<clusterName>`.
- The product type is `KubeRocketCI` (configurable). Products and engagements are created on demand. Imports use `reimport-scan` with `close_old_findings`, `deduplication_on_engagement`, `environment=Development` and `push_to_jira=false`.
- **Ownership.** The operator touches (closes) only tests that carry its `krci-cluster:<clusterName>` tag and a `krci-scope` of `runtime`, `tenant` or `platform`.
- **Component tag.** It is derived from the top workload object (Deployment, StatefulSet, DaemonSet, CronJob, Job or Pod, read with a metadata `get`) and lower-cased into a tag-safe value: spaces and commas become `-`. The first source present wins:
  1. the app part of the annotation `argocd.argoproj.io/tracking-id` (the text before the first `:`, after the last `_`), with the configured `componentPrefixes` stripped;
  2. the label `argocd.argoproj.io/instance`;
  3. the label `app.kubernetes.io/part-of`;
  4. the annotation `meta.helm.sh/release-name`;
  5. the label `app.kubernetes.io/instance`;
  6. the namespace name.

## Installation

The Helm chart in [deploy-templates](deploy-templates/README.md) is the distribution artifact.

1. Create the credentials Secret in the namespace of the operator. It holds the address and the API token of the DefectDojo of this cluster:

    ```bash
    kubectl create secret generic defectdojo-credentials -n <namespace> \
      --from-literal=url=https://defectdojo.example.com \
      --from-literal=token=<api-token>
    ```

2. Install the chart:

    ```bash
    helm repo add epamedp https://epam.github.io/edp-helm-charts/stable
    helm install krci-security-operator epamedp/krci-security-operator --version <chart_version> -n <namespace> \
      --set defectdojo.secretName=defectdojo-credentials \
      --set clusterName=<cluster-name>
    ```

One instance serves one cluster and one DefectDojo. Tenants have no access to its namespace.

## Configuration

The chart maps its values to environment variables of the manager. The full list with the defaults is in [deploy-templates/README.md](deploy-templates/README.md).

| Value | Environment variable | Default |
|---|---|---|
| `defectdojo.secretName` | `DEFECTDOJO_SECRET_NAME` | `defectdojo-credentials` |
| `defectdojo.productType` | `DEFECTDOJO_PRODUCT_TYPE` | `KubeRocketCI` |
| `defectdojo.platformProduct` | `DEFECTDOJO_PLATFORM_PRODUCT` | `platform` |
| `clusterName` | `CLUSTER_NAME` | `in-cluster` |
| `scopes.stage`, `scopes.tenant`, `scopes.platform` | `SCOPE_STAGE`, `SCOPE_TENANT`, `SCOPE_PLATFORM` | `true` |
| `excludeNamespaces` | `EXCLUDE_NAMESPACES` (comma-separated globs) | none |
| `componentPrefixes` | `COMPONENT_PREFIXES` (comma-separated) | `in-cluster-` |
| `resyncPeriod` | `RESYNC_PERIOD` | `30m` |
| `concurrency` | `CONCURRENCY` | `2` |
| `reportKinds` | `REPORT_KINDS` (comma-separated) | `VulnerabilityReport`, `ExposedSecretReport` |

The operator also reads `POD_NAMESPACE`, which the chart sets from the pod's namespace. Invalid values stop the manager at start with a message that names the variable.

### Access

The ClusterRole is read-only and grants what the code calls:

| Resource | Verbs | Used for |
|---|---|---|
| `vulnerabilityreports`, `exposedsecretreports` (`aquasecurity.github.io`) | `list`, `watch` | the metadata watch and the full reports of a namespace |
| `replicasets` (`apps`) | `list` | workload resolution |
| `deployments` (`apps`), `jobs` (`batch`) | `get`, `list` | workload resolution and the component tag |
| `statefulsets`, `daemonsets` (`apps`), `cronjobs` (`batch`), `pods` | `get` | the component tag |
| `namespaces` | `list`, `watch` | classification |
| `stages` (`v2.edp.epam.com`) | `list`, `watch` | classification |
| `codebaseimagestreams` (`v2.edp.epam.com`) | `list` | the codebase product of the stage scope |

In its own namespace the operator can `get` the credentials Secret, use `leases` for leader election and `create` events. It writes nothing else to the cluster.

## Development

```bash
make build         # linux binary to dist/manager-$(GOARCH)
make test          # unit tests
make lint          # golangci-lint
make helm-docs     # regenerate deploy-templates/README.md
make validate-docs # fail when the generated chart docs are stale
```

See [docs](docs/README.md) for the layout of the code and the plan for further modules, and [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention.

## Contributing

We welcome contributions in the form of issues and pull requests. Please follow the contributing guidelines outlined in the repository.

## License

This project is licensed under the [Apache License 2.0](LICENSE.txt).
