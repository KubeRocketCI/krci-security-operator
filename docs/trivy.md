# Trivy module

The `trivy` module (`internal/controller/trivy`) imports Trivy Operator `VulnerabilityReport` and `ExposedSecretReport` objects of every namespace into the cluster's DefectDojo. Installation is in the [README](../README.md), the chart values in [../deploy-templates/README.md](../deploy-templates/README.md).

## How it works

The operator reads only Kubernetes and Trivy Operator objects: Namespaces, workloads, reports and its credentials Secret. It reads no KubeRocketCI resource or label, so it works the same on a cluster without KubeRocketCI.

The unit of work is a namespace. The operator reconciles a namespace when a `VulnerabilityReport` or `ExposedSecretReport` in it changes, when the namespace is created, deleted or starts terminating, and every `resyncPeriod`.

1. **Skip** namespaces that match `excludeNamespaces`.
2. **Reimport**: list the namespace's reports, resolve each to its stable workload (a ReplicaSet to its Deployment, a Job to its CronJob; a StatefulSet, DaemonSet or Pod is its own workload), and reimport only the reports whose UID or resourceVersion changed since the last reimport. The state is in memory, so a restart reimports once. Reimports into one test are serialized. See [Current report](#current-report) for the reports that are not reimported.
3. **Close**, after each pass over an imported namespace, the owned tests of the namespace product whose title no live workload container calls for (see [Close rules](#close-rules)). A namespace that is gone or excluded has every active finding of all its owned tests closed, once per process. Closing mitigates the findings; the product and the tests stay, and a later reimport reactivates the findings. A close and a reimport of one test never run at the same time.
4. **Product tags**: every pass over a namespace, imported, gone or excluded, reads its product and sets the missing or wrong tags (see [DefectDojo naming](#defectdojo-naming)). A failed update fails the pass after the closing, so the workqueue retries it.
5. **Sweep**: at start and every 6 hours, list the namespace products of the cluster and hand to the controller the namespaces that no longer exist or are excluded and are not closed yet, and the namespaces whose product has wrong or missing tags. The sweeper writes nothing to DefectDojo: the controller closes the tests and sets the tags, so all writes of a namespace are serialized with its imports.

### Errors, requeues and API load

- A transient failure (a Kubernetes read, a DefectDojo call, closing a test) is returned from the reconcile, so the workqueue backs off exponentially (30 seconds up to 10 minutes) and `controller_runtime_reconcile_errors_total` counts it.
- DefectDojo calls: a re-import is never retried after a timeout, a transport error or a 5xx, because DefectDojo may still be processing it and a second import into the same test duplicates findings; only a 429 is retried. Reads and the finding close call, which is idempotent, are retried with backoff. A re-import may take 10 minutes, every other call 2 minutes. The manager never stops for it.
- An absent optional dependency is not an error. While the credentials Secret is missing or has no `url` or `token`, the namespace is requeued after at most 5 minutes; the missing Secret is logged once per process at Info and then at debug level. While no report CRD is served, the namespace is requeued every `resyncPeriod`.
- A report that DefectDojo rejects with a client error (4xx) is not uploaded again for the rest of `resyncPeriod`: the version (UID and `resourceVersion`) and the time of the upload are remembered at once, also when the pass fails later. A pass that runs at least 90% of `resyncPeriod` after the last upload of the version uploads it again, so the periodic pass retries it once per period; a fixed cause, such as a product moved to the configured Product Type, lets the retry succeed. A version that is rejected again waits another period and is not logged at Error or counted again; a retry that fails with another error keeps the rejection, so the next pass retries it without a new Error log or count. A changed report is uploaded at once. A rejection does not fail the pass, so the close rules still run, and an earlier reimport of the same workload stays as it is. Each newly rejected version is logged at Error once and counted in the metric `krci_security_operator_rejected_reports_total{kind}`. The memory is lost on restart.
- A broken report is never uploaded: DefectDojo reads it as a report without findings and closes every finding of its test. A report is broken when it has no `trivy-operator.resource.kind` label, no resource name (the `trivy-operator.resource.name` label, else the annotation of the same name), no `trivy-operator.container.name` label, no `report` block, or no result list: `report.vulnerabilities` for a `VulnerabilityReport`, `report.secrets` for an `ExposedSecretReport`. The pass logs it at Info (`Skipped a broken report`, with the reason) and does not count it as imported. A broken report is a missing report: it closes nothing and keeps nothing open; the close rules decide, so its test stays open while its workload and container are live. A report with an empty result list is not broken: it is uploaded and closes the findings of its test.
- Every namespace is requeued every `resyncPeriod`, spread by up to 10% either way.
- Only the listing of a report kind (reports or their metadata) may find the kind not served; a 404 on a workload list fails the pass. While a configured report kind is not served, also when it stops being served while its pages are listed, its reports are not imported, what the operator remembers about them stays, and the pass logs the kind at Info. The close rules do not read reports, so they apply to its tests as to any other. A test of a kind that is not in `reportKinds` is closed.
- A failed upload (a 5xx, a timeout or a transport error: the DefectDojo result is unknown) does not stop the other uploads and the close rules of the pass. The operator closes nothing for that report, returns the error at the end of the pass, and uploads the report again in the next pass.
- An expired continue token (HTTP 410) starts the listing again, up to 3 times; this holds for the lists of reports, of report metadata and of workloads. The reports reimported or rejected before are skipped as unchanged, and a report deleted in between no longer counts as current. After the third restart the pass fails and closes nothing; the retry skips the reports reimported so far, so a large namespace converges over a few passes.
- The credentials Secret is read at most once per minute. Report events that change no `resourceVersion` (informer resyncs) are dropped.
- Report kinds are discovered at start. A CRD installed later needs an operator restart to be watched; its namespaces still catch up on the next resync.
- Every pass over a namespace, also one over a gone or excluded namespace, reads its product by exact name: one product, with its tags. A sweep lists the namespace products of the cluster once.

The manager serves `controller_runtime_reconcile_errors_total` and `krci_security_operator_rejected_reports_total` when `metrics.enabled` is true: plain HTTP on `metrics.port` (8080) of the pod. The chart creates no Service for them.

`metrics.enabled` is `false` by default and then nothing is served. To read the metrics, set it to `true`, forward the port and request the path `/metrics`: `kubectl -n <namespace> port-forward <pod> <metrics.port>:<metrics.port>`, then `curl -s localhost:<metrics.port>/metrics | grep krci_security_operator_rejected_reports_total`. Without metrics, a newly rejected report version is also in the pod log as one Error entry `DefectDojo rejected a report version` with the fields `report` and `kind`; the counter and the entries count the same versions, and both start again at a restart.

### Sizing

Reports are listed 10 at a time (`reportsPageSize` in `internal/controller/trivy/reconciler.go`). Each page is resolved and imported before the next is read, a report is released as soon as it is imported, and the payload shares the report body instead of copying it (only a report that holds repeated entries gets a copy of its block and result list), so only the small sets of reimported tests and chosen reports are kept across pages. The payload of a report with several entries also builds a set of entry keys, 32 bytes per entry, that is released when the payload is built. The peak per reconcile is one page of reports plus the marshalled payload of one report. The memory of the manager scales with `concurrency` multiplied by that peak (a report can reach 3 MB, so a page is up to 30 MB), plus the metadata of all reports in the cluster, plus the names, container names and container image references of the workloads of a namespace and the metadata of the reports of one kind of a namespace (see Watches and reads). The chart defaults are a 128Mi request and a 512Mi limit; raise the limit when `concurrency`, the report sizes or the number of workloads grow.

### Watches and reads

- The controller watches the metadata of `VulnerabilityReport` and `ExposedSecretReport` only (`metav1.PartialObjectMetadata`), because a report can reach 3 MB. Each event enqueues the namespace of the report.
- It also watches Namespaces (creation, deletion and the start of the termination).
- Everything else is read without a cache, through the API reader: the full reports of a namespace, the workloads (ReplicaSets, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs; of Pods only the metadata, and the full object of each Pod without a controller), the labels and annotations of the top workload and the credentials Secret. Each kind is listed at most once while the reports are imported and once more when the close decision is made, so a workload created in between is seen. The lists of the import are released before the lists of the close decision are read. ReplicaSets, Deployments, Jobs, StatefulSets, DaemonSets, CronJobs and the metadata of Pods are listed 500 at a time, and only names, owners, revisions, creation times, container names and the image reference of each container are kept. The metadata of the reports of a kind is listed 500 at a time, once per pass, when a report of a ReplicaSet or Job is compared with the reports on its workload.

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

- **Test tags.** Every reimport sends the full tag list of the test; DefectDojo replaces the tags of the test with it. A tag is `<key>:<value>`, the value in lower case with spaces, commas, `'` and `"` replaced by `-`, one tag per key, at most 255 characters (see Length limits):

  | Tag | Value |
  |---|---|
  | `k8s-cluster` | `<clusterName>` |
  | `k8s-namespace` | `<namespace>` |
  | `k8s-workload` | `<kind>.<name>` of the stable workload, the kind in lower case (`deployment`, `statefulset`, `daemonset`, `cronjob`, `job`, `replicaset`, `pod`), so the kind ends at the first `.` |
  | `k8s-container` | `<container>` |
  | `oci-image` | `<registry>/<repository>` of the image of the report, without tag and digest; Docker Hub without host and `library/`. Left out when the report names no image. |
  | `app` | the component, only when a source exists (see Component) |

  The tags are for filtering; the operator never reads them back to identify a test. A `k8s-workload` tag over 255 characters has its value shortened, so it is not the full workload name. Findings carry no operator tags: DefectDojo adds the tags of a request to findings and never removes them, so they would keep old images and apps. Filter findings by the tags of their test (`test__tags`). The tags that findings do carry come from the DefectDojo parser, see Findings.
- **Findings.** The DefectDojo Trivy Operator parser builds them from the report; the operator sends no finding fields, only the report with its labels rewritten to the stable workload.
  - Identity: DefectDojo hashes the title, the severity, the vulnerability ids and the description of a finding, and always the service (`HASH_CODE_FIELDS_ALWAYS`). The workload is in the hash through the description. For a vulnerability finding the title is `<vulnerability id> <package> <installed version>` and the description holds the vulnerability title, the fixed version, the container and the resource kind, name and namespace. For an exposed secret finding the title is `Secret detected in <target> - <title>`, there are no vulnerability ids, and the description holds the title, the category, the match, the container, the resource kind, name and namespace, and the rule id.
  - Repeated entries (ADR 0005): the operator sends each entry once. A report can hold entries that DefectDojo hashes equal, and nothing in them tells the two apart. With `enable_deduplication=false`, the DefectDojo default, the first upload of a test creates an active finding for each of them; a reimport matches all of them to the lowest-ID finding of the hash and closes the others, though the report still holds them. So the payload rewrite also drops an entry whose key repeats an earlier one, and keeps the first. The first reimport after the upgrade closes the duplicate findings of tests uploaded before this change. Two occurrences of one secret rule in one target with the same match are one finding. The key is the hash input of the finding that the parser builds from the entry, without the parts that are equal in one payload (the labels and the service): the title, the severity, the vulnerability id and the description. It is built from `vulnerabilityID`, `resource`, `installedVersion`, `severity`, `title` and `fixedVersion` for a vulnerability, and from `target`, `title`, `category`, `match`, `severity` and `ruleID` for a secret. The fields are read as the parser reads them: an absent field is its default (`0` for `vulnerabilityID` and `ruleID`, empty for `match` and `target`, `None` for the others), a null field is `None`, and an empty field is empty. An absent field therefore equals its literal default, and differs from an empty field except for `match` and `target`. Case is ignored, as in the hash (Unicode case folding). Other fields (`score`, `target` of a vulnerability, `packagePath`, `links`) are not part of the key, so the `score` of a dropped entry is not sent. The key follows the parser and the hash fields of DefectDojo 3.5.200 (see DefectDojo requirements); another version that builds or hashes other fields needs the key changed with them.
  - The key is stricter than the hash in these cases, which only keep an entry: a key field that is not a string or null; parts that differ but join to the same hash input, since the hash has no separators between them; a blank vulnerability id next to another blank one, which differ in the title only by leading whitespace that the hash strips.
  - Tags: the parser tags a vulnerability finding with the namespace (the value of the label `trivy-operator.resource.namespace`), the package type and the class of its target (`os-pkgs`, `lang-pkgs`), and an exposed secret finding with the namespace.
  - Severity: `CRITICAL`, `HIGH`, `MEDIUM` and `LOW` map to `Critical`, `High`, `Medium` and `Low`; `UNKNOWN` is imported as `Info`. `minimum_severity` is `Info`, so no severity is left out.
- Every namespace product carries the tags `k8s-cluster:<clusterName>` and `k8s-namespace:<namespace>`. The operator sets them when the product has them wrong or missing, on every pass over the namespace (a sweep wakes the namespaces that need it), and keeps the other tags of the product. An update replaces the tags of a product, so the full list is sent.
- The same namespace name in two clusters gives two products, because the cluster name is part of the product name. The cluster name is required and must be unique per DefectDojo; two clusters with one name write into the same products.
- Use one Product Type value for every operator that writes to the same DefectDojo. A reimport fails when the product already exists under another Product Type, so changing the value later leaves the existing products under the old one.
- Products, engagements and tests are created on demand. Imports use `reimport-scan`; see [Reimport request](#reimport-request).
- **Ownership.** An owned test is a test whose product name starts with `<clusterName>/` and whose scan type is `Trivy Operator Scan`. The operator closes only owned tests, so it never closes a test of another cluster, also when the namespace names are equal. A product whose name only contains `<clusterName>/` (`x-<clusterName>/<namespace>`), a codebase product of the CI pipeline and a test of another scan type are not owned. Tags are not used for ownership.
- **Lookups.** The tests of a namespace are found through its product (the exact name `<clusterName>/<namespace>` under the Product Type, asked with the `name_exact` filter, which ignores case, so the operator compares the name again), the engagement `trivy-operator` of the product, and the tests of the engagement with the scan type `Trivy Operator Scan`. The products of the cluster are listed by Product Type and the name `<clusterName>/`; DefectDojo matches names by "contains", so the operator checks the prefix. Lists are read page by page. The ID of the Product Type is kept until a list of products under it comes back empty. A Product Type that DefectDojo does not list (not created yet, or not readable by the token) is logged at Info once per process; no product is looked up, and a gone or excluded namespace is not recorded as released, so the next pass looks again. A close mitigates the findings of the test with `active=true` and `is_mitigated=false`.
- **Close cases.** See [Close rules](#close-rules).

- **Reimport request.** Every report is sent with these fields; `apply_tags_to_findings` is not sent:

  | Field | Value |
  |---|---|
  | `scan_type` | `Trivy Operator Scan` |
  | `product_type_name`, `product_name`, `engagement_name`, `test_title` | the layout above |
  | `service` | `<namespace>/<Kind>/<name>/<container>`, the kind and name of the stable workload (`Deployment`, `CronJob`, else the kind of the report). It is the service the Trivy Operator parser builds from the report labels `trivy-operator.resource.namespace`, `.kind`, `.name` and `trivy-operator.container.name`, which the operator rewrites to the stable workload and the namespace before the upload, so a rollout keeps one service; the request service replaces the parser service of every finding, and a value over 200 characters is shortened as described under Length limits. DefectDojo closes, on reimport, only the findings of the request service |
  | `version` | the `artifact.tag` of the report, else `sha256:` and the first 12 characters of `artifact.digest`. A container reference in the pod template of the stable workload that is a digest without a tag, equal to `artifact.digest`, has no tag: `artifact.tag` is not used for it. In every other case the report decides |
  | `tags` | one field per tag of the test |
  | `auto_create_context`, `close_old_findings`, `deduplication_on_engagement`, `active` | `true` |
  | `verified`, `push_to_jira` | `false` |
  | `minimum_severity` | `Info` |
  | `environment` | `Development` |
  | `scan_date` | today, date only |

  The workload name is the `trivy-operator.resource.name` label, else the annotation of the same name: Trivy Operator writes a name that is not a valid label value only to the annotation. The label rewrite always writes the full name.
- **Length limits.** DefectDojo stores at most 200 characters of the service, 255 of the test title, of the product name and of a whole tag (`<key>:<value>`), and 100 of the version. A longer service, title, version or tag value is shortened: its start, `~` and the first 12 hex characters of the SHA-256 of the full value, to the limit; a tag keeps its `<key>:` prefix and only the value is shortened. The same value always gives the same result. The product name never reaches its limit: the cluster name and the namespace are DNS labels. A shortened tag value is not parsed back.
- **Component.** The `app` tag is derived from the top workload object (Deployment, StatefulSet, DaemonSet, CronJob, Job or Pod, read with a metadata `get`) and lower-cased into a tag-safe value: spaces, commas, `'` and `"` become `-`. The first source present wins:
  1. the app part of the annotation `argocd.argoproj.io/tracking-id` (the text before the first `:`, after the last `_`), with the configured `componentPrefixes` stripped;
  2. the label `argocd.argoproj.io/instance`;
  3. the label `app.kubernetes.io/part-of`;
  4. the annotation `meta.helm.sh/release-name`;
  5. the label `app.kubernetes.io/instance`.

  A workload without a source, or one that no longer exists, has no `app` tag.

### Current report

A report is imported only when it describes a workload as it is now:

- A ReplicaSet owned by a Deployment: only the report of the ReplicaSet whose `deployment.kubernetes.io/revision` equals that of its Deployment. Reports of older ReplicaSets are not imported.
- A report marked with the TTL `0s` (annotation `trivy-operator.aquasecurity.github.io/report-ttl`), which Trivy Operator deletes at once, is not imported.
- A Job owned by a CronJob: only the report of its newest Job, imported as the CronJob. The report on the CronJob itself is current as well. A Job without a CronJob is its own workload, as is a ReplicaSet without a Deployment.
- The workload must exist, and the container of the report must be in the pod template of the workload (containers and init containers; also ephemeral containers of a Pod). Otherwise the report is history and is not imported, also when Trivy Operator keeps it.
- ReplicationController reports, and reports of any kind other than the workloads above, are not imported.

When two current reports give one test title (the report on a CronJob and the report on its newest Job, for example), one is used on every pass and the other is logged at Info (`Ignored a report of a test that has another current report`, with `used` and `ignored` report names): the report on the stable workload itself comes first, then the lowest report name. A report on a ReplicaSet or a Job is not uploaded while a current report of the same container names the stable workload itself, whichever of the two the listing delivers first. The report on the workload is found in the metadata of the reports of the kind (resource kind, resource name from the label or else the annotation, and container name). It counts only when it can be uploaded: it is not marked for deletion, not expired, not broken and not of a rejected version whose retry is not due. Each report that loses is logged once per pass.

### Close rules

The operator closes a test (mitigates its active findings, keeps the test and its history) in these cases only:

- The stable workload is gone: the Deployment, StatefulSet, DaemonSet, CronJob, standalone ReplicaSet, Job or Pod does not exist any more. A workload created again with the same name reactivates the findings through the next reimport, because the report is imported again.
- The container is not in the pod template of the stable workload, as a removed sidecar. This holds also when Trivy Operator keeps the old report.
- The namespace is deleted, terminating or excluded.

The decision does not read reports. Each pass builds the set of titles that the workloads call for, from lists read when the close is decided, one per report kind in `reportKinds`, stable workload and container of its pod template (the title of the import, shortened in the same way), and closes an owned test whose title is not in it. So:

- A missing report never closes a test. Trivy Operator deletes a report when its TTL expires (24 hours by default) and writes it again after the next scan, does not scan an excluded image, and keeps the old report after a failed scan. The test of a container whose image Trivy Operator excludes stays open with its last findings.
- A workload scaled to zero is not gone: a Deployment, StatefulSet or a ReplicaSet of replicas 0 keeps its tests open until it is deleted. A ReplicaSet whose controller is not a Deployment (an Argo Rollouts Rollout, a custom controller) is a workload of its own: each old ReplicaSet that the controller keeps at 0 replicas has its own test and keeps its findings active until the ReplicaSet is deleted.
- A test of an older version of the operator, or of a workload kind the operator does not read, has no title in the set and is closed.
- When a workload list fails, nothing is closed in the pass.
- A report that is not uploaded (a broken report, a rejected version, a failed upload) leaves its test as it is.

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

- DefectDojo 3.5.200 is the tested and recommended version; earlier versions may work but are not tested.
- The system setting `enable_deduplication` is off (the default), and `HASHCODE_FIELDS_PER_SCANNER` for `Trivy Operator Scan` is the default `title`, `severity`, `vulnerability_ids`, `description`, with `HASH_CODE_FIELDS_ALWAYS` = `service`. The operator drops repeated entries by these hash fields; another configuration needs the key changed with it.
- The API token user is a superuser, a staff user, or an authorized user of the Product Type or of the product. DefectDojo 3.5.200 checks the superuser and staff flags and the authorized users only, and does not read role assignments.

| Used for | Token user |
|---|---|
| lookups, the active findings of a test, reimport, product tags, close | a superuser, a staff user, or an authorized user of the Product Type (or of the product) |
| creation of products and engagements on first use | a superuser, a staff user, or an authorized user of a Product Type created in advance |
| creation of the Product Type on first use | a superuser or a staff user; a non-staff user with the Django permission `dojo.add_product_type` can create it, but DefectDojo 3.5.200 does not make that user a member of it, so the token cannot use it afterwards |

Create the Product Type in advance and add the token user to its authorized users when the token is not a staff user.

### Access

The ClusterRole is read-only and grants what the code calls:

| Resource | Verbs | Used for |
|---|---|---|
| `vulnerabilityreports`, `exposedsecretreports` (`aquasecurity.github.io`) | `get`, `list`, `watch` | the metadata watch, the full reports of a namespace, and the body of a report on the stable workload that was never imported |
| `replicasets` (`apps`) | `list` | workload resolution and the close rules |
| `deployments` (`apps`), `jobs` (`batch`) | `get`, `list` | workload resolution, the close rules and the component tag |
| `statefulsets`, `daemonsets` (`apps`), `cronjobs` (`batch`), `pods` | `get`, `list` | `list`: the containers of the workloads and the close rules, Pods by metadata only; `get`: the component tag and the full object of a Pod without a controller |
| `namespaces` | `list`, `watch` | the reconcile key, deleted and excluded namespaces |

A Role in the release namespace (`leader_election_role.yaml`) grants the rest:

| Resource | Verbs | Used for |
|---|---|---|
| `secrets`, only the name in `defectdojo.secretName` (`resourceNames`) | `get` | the credentials Secret; no other Secret can be read, and the Secret cannot be listed or watched |
| `leases` (`coordination.k8s.io`) | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | leader election |
| `events` | `create` | events of the manager |

The operator writes nothing else to the cluster.
