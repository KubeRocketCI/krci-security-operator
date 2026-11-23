# Allowlisted namespace and workload labels become tags

The installer lists label keys in two settings, `labelTags.namespace` (`NAMESPACE_LABEL_TAGS`) and `labelTags.workload` (`WORKLOAD_LABEL_TAGS`), both empty by default. For each listed key that a Namespace has as a label, the operator writes the tag `<label key>:<label value>` on its namespace product. For each listed key that a workload has as a label, it writes the same kind of tag on the tests of that workload. The tag key is the label key, with no prefix, so a reader filters by the name the platform already uses. The operator names no label itself and no default lists one, so it still reads no KubeRocketCI data (ADR 0001): a platform that labels its namespaces with a tenant lists that key. We chose this because administrators and portals tell the namespaces and workloads they manage from the others by labels of their own, which the layout of ADR 0002 does not carry.

## Considered Options

- Copy every label. Rejected: labels of unrelated tooling (the Pod Security labels, `kubernetes.io/metadata.name`) would become tags, and any label change would upload reports again.
- Name the KubeRocketCI labels in the operator. Rejected by ADR 0001.
- Prefix the tag key. Rejected: readers filter by the label key of their platform.
- Put the namespace label tags on every test of the namespace. Rejected: the product is where a reader finds the namespace, and a namespace label change would upload every report of the namespace.
- Read a workload label from the ReplicaSet or the pod template. Rejected: the top workload object is read already for the `app` tag, so the labels need no new read and no new RBAC verb.
- Tag the findings. Rejected: DefectDojo adds the tags of a reimport to findings and never removes them (ADR 0003).

## Consequences

- A namespace product has the label tags of the keys of `labelTags.namespace` next to `k8s-cluster` and `k8s-namespace`. A test has the label tags of the keys of `labelTags.workload` next to its operator tags. Each has one tag per key. A finding has none (ADR 0003).
- The key is in lower case, the case DefectDojo stores the tags of a test in; a product tag keeps the case it is sent in, so the operator writes lower case on both. The value is made tag-safe, and a tag over 255 characters is shortened as every tag is (`docs/trivy.md`, Length limits). A key that the object lacks, and a label with an empty value, give no tag.
- A workload label is read from the object the `app` tag is read from: the Deployment, StatefulSet, DaemonSet or CronJob, a Job without a CronJob, or a Pod. This lifts "no labels or annotations" of the workload lists for the listed keys. A ReplicaSet without a Deployment has none, as it has no `app` tag.
- The settings are checked at start. A key must be a valid Kubernetes label key, at most 191 characters so that its tag fits 255 with a label value of 63, and no two keys of a list may give the same tag key. A key that gives a tag key the operator writes itself (`k8s-cluster`, `k8s-namespace`, `k8s-workload`, `k8s-container`, `oci-image`, `app`, `report-kind`) stops the manager with an error that names the variable and the key. The list is built from the tag key constants (`trivy.ReservedTagKeys`).
- The operator owns the product tags whose key is `k8s-cluster`, `k8s-namespace` or a key of `labelTags.namespace`. A pass over an imported namespace sets the tag of each label, corrects a wrong value, removes the tag of a label that is gone, and keeps every other tag; a tag of a listed key that a person wrote is replaced or removed. A key that leaves the list is no longer owned: its tags stay on the products. A namespace that is gone, terminating or excluded is not followed: its product keeps its label tags.
- A change of a listed namespace label wakes the namespace through the Namespace watch, and the pass corrects the product. It uploads no report.
- The workload label tags are part of the tag list of every reimport, so part of the upload marker (ADR 0006). A changed `labelTags.workload`, a changed value and a removed label change the tags of the affected tests, and each is uploaded once on the next pass over its namespace. A list change that leaves every request as it was, a key that no workload has as a label, uploads nothing. Workloads are not watched: a changed workload label is seen on a report event or the resync. The request format version is not bumped.
- With both settings empty the products, tests and upload markers are those of the operator without the settings.
- The ClusterRole is unchanged: the Namespaces and the workload lists are read already.
- A tag is as trustworthy as the right to edit its object. The developers of a namespace write its workload labels, so a reader that needs proof of an owner trusts a namespace label.
