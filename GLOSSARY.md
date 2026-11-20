# Runtime security sync

The operator copies the Trivy Operator reports of one cluster into a shared DefectDojo, so that every finding shows the cluster, namespace, workload, container and image where it is.

## Kubernetes side

**Cluster name**:
The unique name of one cluster in the shared DefectDojo, set by the person who installs the operator.
_Avoid_: cluster id, context, in-cluster (as a meaning)

**Stable workload**:
The workload that keeps its name across rollouts: the Deployment of a ReplicaSet, the CronJob of a Job, or the object itself for every other kind.
_Avoid_: resource, owner, ReplicaSet (for a Deployment)

**Container**:
A named container of the pod template of a stable workload, init and ephemeral containers included.
_Avoid_: image (for the container)

**Image**:
The registry and repository that a container runs, without tag and digest. The tag or digest is the version.
_Avoid_: artifact, container (for the image)

**Report**:
One Trivy Operator object about one container of one workload: a VulnerabilityReport or an ExposedSecretReport.
_Avoid_: scan, result

**Report version**:
The UID and resourceVersion of a report. The content of a report does not change while its version holds.
_Avoid_: revision (the Deployment's word), generation

**Current report**:
A report of a stable workload's live revision whose container is still in the pod template.
_Avoid_: latest report, fresh report

**Missing report**:
A container that exists but has no current report, for example between a TTL deletion and the next scan. It means "not scanned", never "clean".
_Avoid_: empty report, clean

**Empty report**:
A current report with zero vulnerabilities or secrets. It means "clean".
_Avoid_: missing report

**Broken report**:
A report without the resource kind label, without the resource name (label or annotation), without the container name label, without the `report` block, or without its result list. It is never uploaded.
_Avoid_: empty report, malformed report, invalid report

## DefectDojo side

**Product Type**:
The DefectDojo group of products that the operator writes into; set by the person who installs the operator, `KubeRocketCI` by default.
_Avoid_: organization, tenant

**Product**:
The DefectDojo object that one owner secures, with its own members, SLA and dashboard.
_Avoid_: asset, project

**Namespace product**:
The product of one namespace of one cluster, named `<cluster name>/<namespace>`.
_Avoid_: environment product, tenant product

**Codebase product**:
The product of one codebase, written by the CI pipeline.
_Avoid_: application product

**Engagement**:
A context of work inside a product. A namespace product has one engagement for each integration that writes to it; the Trivy integration uses `trivy-operator`.
_Avoid_: scope, environment (for the engagement)

**Runtime test**:
The DefectDojo test of one report kind, stable workload and container in a namespace product.
_Avoid_: scan, report (for the test)

**Finding**:
One issue in a test, identified by DefectDojo from its title, severity, vulnerability ids, description and service.
_Avoid_: vulnerability (for the finding), issue

**Repeated entry**:
A result entry of a report that DefectDojo would give the same finding identity as an earlier entry of the same report. The operator sends the first and drops the rest.
_Avoid_: duplicate, duplicate finding (DefectDojo's term for a finding flagged by deduplication)

**Service**:
The finding field that names the stable workload and container: `<namespace>/<Kind>/<name>/<container>`.
_Avoid_: component, workload (for the field)

**Tag**:
A `<key>:<value>` label on a product or test, used for filters. The operator writes none on findings. On a test, `k8s-workload` and `k8s-container` also name its stable workload and container.
_Avoid_: label (for DefectDojo tags)

**Namespace label tag**:
The tag `k8s-ns-label.<label key>:<value>` that the operator copies from a Namespace label whose key the installer lists in `namespaceLabelTags`. It is on the namespace product and on every runtime test of the namespace, and the operator owns its prefix on the product.
_Avoid_: tenant tag, environment tag, workload label tag

## Sync

**Producer**:
A system that writes to DefectDojo: the CI pipeline or the operator. Each producer writes only its own products.
_Avoid_: importer, client

**Reimport**:
An upload of one current report into its runtime test, which matches existing findings and closes the ones the report no longer holds.
_Avoid_: import, sync (for one upload)

**Upload marker**:
The `build_id` of a runtime test that names the report version and the request of the last completed reimport into it. A test whose reimport did not complete has no marker or the earlier one. A report whose marker equals it is already uploaded.
_Avoid_: checkpoint, fingerprint (for the whole value), imported flag

**Workload report**:
A report whose resource is the stable workload itself, not a ReplicaSet or Job of it.
_Avoid_: own report

**Chosen report**:
The current report a runtime test is reimported from when several current reports give one test title: the workload report first, then the lowest report name.
_Avoid_: claimed report, winning report

**Rejected report version**:
A report version that DefectDojo rejected with a client error. It is uploaded again once per `resyncPeriod`, and logged at Error and counted once.
_Avoid_: failed report, bad report

**Released namespace**:
A namespace that is gone, terminating or excluded and whose owned tests the operator closed. Its product and tests stay.
_Avoid_: deleted namespace, cleaned namespace

**Close**:
Mark a finding mitigated. A closed finding stays in DefectDojo and can be reactivated.
_Avoid_: delete, remove, resolve

**Close a test**:
Mitigate the active findings of an owned test and keep the test. A reimport of a report without results does it per service; findings that stay active are closed one by one.
_Avoid_: delete a test, clean a test

**Empty reimport**:
A reimport of a report without results into a test, by test ID, so that DefectDojo mitigates every finding of one service. It is not an upload of a current report.
_Avoid_: empty upload, bulk close

**Reactivate**:
A closed finding that a later reimport matches again becomes active again.
_Avoid_: reopen, recreate

**Owned test**:
A runtime test that this operator may close: its product name starts with `<cluster name>/` and its scan type is `Trivy Operator Scan`.
_Avoid_: managed test, our test
