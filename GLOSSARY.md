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

**Service**:
The finding field that names the stable workload and container: `<namespace>/<Kind>/<name>/<container>`.
_Avoid_: component, workload (for the field)

**Tag**:
A `<key>:<value>` label on a product or test, used for filters. The operator writes none on findings. On a test, `k8s-workload` and `k8s-container` also name its stable workload and container.
_Avoid_: label (for DefectDojo tags)

## Sync

**Producer**:
A system that writes to DefectDojo: the CI pipeline or the operator. Each producer writes only its own products.
_Avoid_: importer, client

**Reimport**:
An upload of one current report into its runtime test, which matches existing findings and closes the ones the report no longer holds.
_Avoid_: import, sync (for one upload)

**Close**:
Mark a finding mitigated. A closed finding stays in DefectDojo and can be reactivated.
_Avoid_: delete, remove, resolve

**Reactivate**:
A closed finding that a later reimport matches again becomes active again.
_Avoid_: reopen, recreate

**Owned test**:
A runtime test that this operator may close: its product name starts with `<cluster name>/` and its scan type is `Trivy Operator Scan`.
_Avoid_: managed test, our test
