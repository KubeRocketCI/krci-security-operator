# The operator reads no KubeRocketCI data

The operator reads only Kubernetes and Trivy Operator objects: Namespaces, the workloads, the reports and its credentials Secret. It reads no `v2.edp.epam.com` resources (Stage, CodebaseImageStream) and no `app.edp.epam.com/*` labels, and it writes no KubeRocketCI names or tags. We chose this so that one operator works on every cluster, including clusters where KubeRocketCI is not installed but deploys workloads, and so that one DefectDojo can hold the data of all clusters. The link between KubeRocketCI concepts (environment, codebase, tenant) and the results is a separate decision.

## Considered Options

- Classify namespaces from Stage and CodebaseImageStream resources (the first version). Rejected: those resources exist only on the KubeRocketCI cluster, so a cluster that only receives deployments gets no environment and no codebase, and only Stages with `clusterName: in-cluster` were ever matched.
- Read KubeRocketCI data from a remote API of the KubeRocketCI cluster. Rejected for now: a second source, credentials across clusters, and a dependency the operator does not need for its main value.

## Consequences

- The product, engagement, test and tags carry Kubernetes names only.
- `KubeRocketCI` remains only as the default Product Type name, which the person who installs the operator can change (ADR 0002). It is a name, not an input.
- Environment, codebase and tenant views need a later decision on how KubeRocketCI connects to the namespace products. The operator offers one generic input for it: the tags of the Namespace labels that the installer lists, which the operator copies without knowing their meaning (ADR 0009).
