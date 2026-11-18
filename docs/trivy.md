# Trivy module

The `trivy` module (`internal/controller/trivy`) imports Trivy Operator `VulnerabilityReport` and `ExposedSecretReport` objects of every namespace into the cluster's DefectDojo. Installation is in the [README](../README.md), the chart values in [../deploy-templates/README.md](../deploy-templates/README.md).

## How it works

The operator reads only Kubernetes and Trivy Operator objects: Namespaces, workloads, reports and its credentials Secret. It reads no KubeRocketCI resource or label, so it works the same on a cluster without KubeRocketCI.

The unit of work is a namespace. The operator reconciles a namespace when a `VulnerabilityReport` or `ExposedSecretReport` in it changes, when the namespace is created, deleted or starts terminating, and every `resyncPeriod`.

1. **Skip** namespaces that match `excludeNamespaces`.
2. **Import**: list the namespace's reports, resolve each to its stable workload (a ReplicaSet to its Deployment, a Job to its CronJob; a StatefulSet, DaemonSet or Pod is its own workload), and re-import only the reports whose UID or resourceVersion changed since the last import. The state is in memory, so a restart re-imports once. Imports into one test are serialized.
3. **Close**, after each pass over an imported namespace, the owned tests of the namespace product that the pass did not import, of the report kinds it listed completely. That covers removed workloads. The findings of other services in a test are closed once per test. A namespace that is gone or excluded has every active finding of all its owned tests closed, once per process. Closing mitigates the findings; the product and the tests stay, and a later reimport reactivates the findings. A close and a reimport of one test never run at the same time.
4. **Product tags**: every pass over a namespace, imported, gone or excluded, reads its product and sets the missing or wrong tags (see [DefectDojo naming](#defectdojo-naming)). A failed update fails the pass after the closing, so the workqueue retries it.
5. **Sweep**: at start and every 6 hours, list the namespace products of the cluster and hand to the controller the namespaces that no longer exist or are excluded and are not closed yet, and the namespaces whose product has wrong or missing tags. The sweeper writes nothing to DefectDojo: the controller closes the tests and sets the tags, so all writes of a namespace are serialized with its imports.

### Errors, requeues and API load

- A transient failure (a Kubernetes read, a DefectDojo call, closing a test) is returned from the reconcile, so the workqueue backs off exponentially (30 seconds up to 10 minutes) and `controller_runtime_reconcile_errors_total` counts it.
- DefectDojo calls: a re-import is never retried after a timeout, a transport error or a 5xx, because DefectDojo may still be processing it and a second import into the same test duplicates findings; only a 429 is retried. Reads and the finding close call, which is idempotent, are retried with backoff. A re-import may take 10 minutes, every other call 2 minutes. The manager never stops for it.
- An absent optional dependency is not an error. While the credentials Secret is missing or has no `url` or `token`, the namespace is requeued after at most 5 minutes; the missing Secret is logged once per process at Info and then at debug level. While no report CRD is served, the namespace is requeued every `resyncPeriod`.
- A report that DefectDojo rejects with a client error (4xx) is permanent for that version: the version (UID and `resourceVersion`) is remembered at once and not uploaded again until the report changes, also when the pass fails later. It does not fail the pass, so stale tests are still closed, and an earlier import of the same workload stays open. Each newly rejected version is logged at Error once and counted in the metric `krci_security_operator_rejected_reports_total{kind}`.
- A broken report is never uploaded: DefectDojo reads it as a report without findings and closes every finding of its test. A report is broken when it has no `trivy-operator.resource.kind` label, no resource name (the `trivy-operator.resource.name` label, else the annotation of the same name), no `report` block, or no result list: `report.vulnerabilities` for a `VulnerabilityReport`, `report.secrets` for an `ExposedSecretReport`. The pass logs it at Info (`Skipped a broken report`, with the reason) and does not count it as imported. Its test stays open with its findings; when the report has no resource kind or name, the pass keeps every test of its report kind open, because the test is unknown. A broken report does not keep the test of a workload that is gone open. A report with an empty result list is not broken: it is uploaded and closes the findings of its test.
- Every namespace is requeued every `resyncPeriod`, spread by up to 10% either way.
- Tests are closed per report kind. While a configured kind is not served, also when it stops being served while its pages are listed, its tests and what the operator remembers about its reports stay as they are, and the pass logs the kind at Info. To close the tests of a kind that is no longer used, remove it from `reportKinds`.
- An expired continue token (HTTP 410) starts the listing of the kind again, up to 3 times. The reports imported or rejected before are skipped as unchanged, and a report deleted in between no longer counts as live. After the third restart the pass fails and closes nothing; the retry skips the reports imported so far, so a large namespace converges over a few passes.
- The credentials Secret is read at most once per minute. Report events that change no `resourceVersion` (informer resyncs) are dropped.
- Report kinds are discovered at start. A CRD installed later needs an operator restart to be watched; its namespaces still catch up on the next resync.
- Every pass over a namespace, also one over a gone or excluded namespace, reads its product by exact name: one product, with its tags. A sweep lists the namespace products of the cluster once.

The manager serves `controller_runtime_reconcile_errors_total` and `krci_security_operator_rejected_reports_total` when `metrics.enabled` is true: plain HTTP on `metrics.port` (8080) of the pod. The chart creates no Service for them.

### Sizing

Reports are listed 10 at a time (`reportsPageSize` in `internal/controller/trivy/reconciler.go`). Each page is resolved and imported before the next is read, a report is released as soon as it is imported, and the payload shares the report body instead of copying it, so only the small sets of live tests and kept-open titles are kept across pages. The peak per reconcile is one page of reports plus the marshalled payload of one report. The memory of the manager scales with `concurrency` multiplied by that peak (a report can reach 3 MB, so a page is up to 30 MB), plus the metadata of all reports in the cluster. The chart defaults are a 128Mi request and a 512Mi limit; raise the limit when `concurrency` or the report sizes grow.

### Watches and reads

- The controller watches the metadata of `VulnerabilityReport` and `ExposedSecretReport` only (`metav1.PartialObjectMetadata`), because a report can reach 3 MB. Each event enqueues the namespace of the report.
- It also watches Namespaces (creation, deletion and the start of the termination).
- Everything else is read without a cache, through the API reader: the full reports of a namespace, ReplicaSets, Jobs, the labels and annotations of the top workload and the credentials Secret.

### DefectDojo naming

Every report of every namespace goes to the namespace product of its cluster:

| Level | Name |
|---|---|
| Product Type | `defectdojo.productType`, default `KubeRocketCI` |
| Product | `<clusterName>/<namespace>` |
| Engagement | `trivy-operator`, created with deduplication on the engagement |
| Test | `<ReportKind> <kind>/<name>/<container>`, without the namespace |

```
KubeRocketCI
└── in-cluster/payments
    └── trivy-operator
        ├── VulnerabilityReport deployment/api/api
        ├── VulnerabilityReport deployment/api/istio-proxy
        └── ExposedSecretReport deployment/api/api
```

- Every test carries `krci-namespace:<ns>`, `krci-workload:<kind>.<name>`, `krci-container:<c>`, `krci-component:<component>` and `krci-cluster:<clusterName>`. The operator does not read them.
- Every namespace product carries the tags `k8s-cluster:<clusterName>` and `k8s-namespace:<namespace>`. The operator sets them when the product has them wrong or missing, on every pass over the namespace (a sweep wakes the namespaces that need it), and keeps the other tags of the product. An update replaces the tags of a product, so the full list is sent.
- The same namespace name in two clusters gives two products, because the cluster name is part of the product name. The cluster name is required and must be unique per DefectDojo; two clusters with one name write into the same products.
- Use one Product Type value for every operator that writes to the same DefectDojo. A reimport fails when the product already exists under another Product Type, so changing the value later leaves the existing products under the old one.
- Products, engagements and tests are created on demand. Imports use `reimport-scan` with `close_old_findings`, `deduplication_on_engagement`, `environment=Development` and `push_to_jira=false`.
- **Ownership.** An owned test is a test whose product name starts with `<clusterName>/` and whose scan type is `Trivy Operator Scan`. The operator closes only owned tests, so it never closes a test of another cluster, also when the namespace names are equal. A product whose name only contains `<clusterName>/` (`x-<clusterName>/<namespace>`), a codebase product of the CI pipeline and a test of another scan type are not owned. Tags are not used for ownership.
- **Lookups.** The tests of a namespace are found through its product (the exact name `<clusterName>/<namespace>` under the Product Type, asked with the `name_exact` filter, which ignores case, so the operator compares the name again), the engagement `trivy-operator` of the product, and the tests of the engagement with the scan type `Trivy Operator Scan`. The products of the cluster are listed by Product Type and the name `<clusterName>/`; DefectDojo matches names by "contains", so the operator checks the prefix. Lists are read page by page. The ID of the Product Type is kept until a list of products under it comes back empty. A Product Type that DefectDojo does not list (not created yet, or not readable by the token) is logged at Info once per process; no product is looked up, and a gone or excluded namespace is not recorded as released, so the next pass looks again. A close mitigates the findings of the test with `active=true` and `is_mitigated=false`.
- **Close cases.**
  - The stable workload of a test is gone: the test is closed.
  - The namespace is deleted, terminating or excluded: every owned test of its product is closed, once per process until the namespace is imported again.
  - A test is imported: once per test and process, the active findings outside the service of the reimport are closed.
- **Component tag.** It is derived from the top workload object (Deployment, StatefulSet, DaemonSet, CronJob, Job or Pod, read with a metadata `get`) and lower-cased into a tag-safe value: spaces and commas become `-`. The first source present wins:
  1. the app part of the annotation `argocd.argoproj.io/tracking-id` (the text before the first `:`, after the last `_`), with the configured `componentPrefixes` stripped;
  2. the label `argocd.argoproj.io/instance`;
  3. the label `app.kubernetes.io/part-of`;
  4. the annotation `meta.helm.sh/release-name`;
  5. the label `app.kubernetes.io/instance`;
  6. the namespace name.

## Configuration

The chart maps its values to environment variables of the manager. The full list with the defaults is in [../deploy-templates/README.md](../deploy-templates/README.md).

| Value | Environment variable | Default |
|---|---|---|
| `defectdojo.secretName` | `DEFECTDOJO_SECRET_NAME` | `defectdojo-credentials` |
| `defectdojo.productType` | `DEFECTDOJO_PRODUCT_TYPE` | `KubeRocketCI` |
| `clusterName` | `CLUSTER_NAME` | none, required: a lowercase RFC 1123 DNS label |
| `excludeNamespaces` | `EXCLUDE_NAMESPACES` (comma-separated globs) | none |
| `componentPrefixes` | `COMPONENT_PREFIXES` (comma-separated) | `in-cluster-` |
| `resyncPeriod` | `RESYNC_PERIOD` | `30m`, at least `1m` |
| `concurrency` | `CONCURRENCY` | `2` |
| `reportKinds` | `REPORT_KINDS` (comma-separated) | `VulnerabilityReport`, `ExposedSecretReport` |

The operator also reads `POD_NAMESPACE`, which the chart sets from the pod's namespace. Invalid values and a missing `CLUSTER_NAME` stop the manager at start with a message that names the variable. The chart does not render without `clusterName`.

### DefectDojo requirements

- DefectDojo 2.55 or later; 3.4.200 or later recommended. Only 3.4.200 and later serialize two imports into one test on the server.
- The API token needs these permissions:

| Permission | Used for |
|---|---|
| read product types, products, engagements, tests and findings | lookups and the active findings of a test |
| import scans | reimport |
| edit products | product tags |
| edit findings | close |
| add Product Type, product and engagement | creation on first use; a Product Type created in advance removes the global add permission |

### Access

The ClusterRole is read-only and grants what the code calls:

| Resource | Verbs | Used for |
|---|---|---|
| `vulnerabilityreports`, `exposedsecretreports` (`aquasecurity.github.io`) | `list`, `watch` | the metadata watch and the full reports of a namespace |
| `replicasets` (`apps`) | `list` | workload resolution |
| `deployments` (`apps`), `jobs` (`batch`) | `get`, `list` | workload resolution and the component tag |
| `statefulsets`, `daemonsets` (`apps`), `cronjobs` (`batch`), `pods` | `get` | the component tag |
| `namespaces` | `list`, `watch` | the reconcile key, deleted and excluded namespaces |

In its own namespace the operator can `get` the credentials Secret, use `leases` for leader election and `create` events. It writes nothing else to the cluster.
