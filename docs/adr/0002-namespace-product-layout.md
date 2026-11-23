# One namespace product per cluster and namespace, one engagement per integration, one test per container

Every namespace of every cluster gets its own namespace product, `<cluster name>/<namespace>`, under one Product Type, a setting with the default `KubeRocketCI`. The product has one engagement for each integration that writes to it; the Trivy integration uses `trivy-operator`, with one runtime test per report kind, stable workload and container: `<ReportKind> <kind>/<name>/<container>`. The engagement is named after the source tool, so a later integration of the operator writes to its own engagement and keeps its own deduplication and close scope. We chose the namespace as the product because it is the unit people own and secure in Kubernetes, and because a DefectDojo product carries its own members, SLA and dashboard. The cluster name in the product name keeps clusters apart, because product names are unique in all of DefectDojo.

## Structure

The contract the operator writes and other systems read. Field and tag rules are in ADR 0003.

```
Product Type   <product type>                              setting, default KubeRocketCI; the same for all operators of one DefectDojo
└── Product    <cluster name>/<namespace>                  product tags: k8s-cluster:<cluster name>, k8s-namespace:<namespace>
    └── Engagement  trivy-operator                         type CI/CD; deduplication on the engagement
        └── Test    "<ReportKind> <kind>/<name>/<container>"
              scan_type  Trivy Operator Scan
              version    <image tag> | sha256:<12 hex>
              tags       k8s-cluster:<cluster name>
                         k8s-namespace:<namespace>
                         k8s-workload:<kind>.<name>
                         k8s-container:<container>
                         oci-image:<registry>/<repository>
                         report-kind:<kind>                vulnerabilityreport | exposedsecretreport
                         app:<component>                   only when a source exists
              └── Finding
                    service   <namespace>/<Kind>/<name>/<container>
                    tags      none from the operator; filter findings by test tag
```

- `<ReportKind>`: `VulnerabilityReport` or `ExposedSecretReport`.
- `<kind>/<name>`: the stable workload, lower-case kind: `deployment`, `statefulset`, `daemonset`, `cronjob`, `job`, `replicaset` (a ReplicaSet without a Deployment), `pod`. ReplicationController reports are not imported.
- On every pass over the namespace, also a gone or excluded one, and when a sweep finds the tags wrong, the operator makes sure both product tags exist with the correct values and keeps other tags, so a failed first attempt is repaired. The sweep only wakes the namespace.
- `<Kind>` in the service: the same kind in Kubernetes spelling: `Deployment`, `CronJob`, …
- The CI pipeline writes codebase products under the same Product Type (`<codebase>`, engagements `code-security-<branch>` and `image:<registry>/<repository>`). The operator never reads or writes them.

Example: two clusters, one DefectDojo.

```
Product Type: KubeRocketCI
├── Product: checkout                                        ← CI pipeline, not the operator
│   └── Engagement: image:registry.example.com/shop/checkout
│       └── Test "Trivy Scan"                                version 2.4.1
├── Product: in-cluster/krci-shop-dev                        tags k8s-cluster:in-cluster, k8s-namespace:krci-shop-dev
│   └── Engagement: trivy-operator
│       └── Test "VulnerabilityReport deployment/checkout/checkout"        version 2.5.0-rc1
│             tags k8s-cluster:in-cluster  k8s-namespace:krci-shop-dev
│                  k8s-workload:deployment.checkout  k8s-container:checkout
│                  oci-image:registry.example.com/shop/checkout  report-kind:vulnerabilityreport
│                  app:checkout
│             service krci-shop-dev/Deployment/checkout/checkout
├── Product: prod-eu/krci-shop-prod                          tags k8s-cluster:prod-eu, k8s-namespace:krci-shop-prod
│   └── Engagement: trivy-operator
│       └── Test "VulnerabilityReport deployment/checkout/checkout"        version 2.4.1
└── Product: prod-eu/payments                                a namespace KubeRocketCI does not manage
    └── Engagement: trivy-operator
        ├── Test "VulnerabilityReport deployment/api/api"                  version 1.8.0
        │     tags k8s-cluster:prod-eu  k8s-namespace:payments
        │          k8s-workload:deployment.api  k8s-container:api
        │          oci-image:registry.example.com/pay/api  report-kind:vulnerabilityreport
        │          app:payments
        │     service payments/Deployment/api/api
        ├── Test "VulnerabilityReport deployment/api/istio-proxy"          version 1.24.0
        │     tags … k8s-container:istio-proxy  oci-image:istio/proxyv2 …
        │     service payments/Deployment/api/istio-proxy
        ├── Test "VulnerabilityReport statefulset/redis/redis"             version 7.4
        │     tags … k8s-workload:statefulset.redis  oci-image:redis  report-kind:vulnerabilityreport  app:redis
        │     service payments/StatefulSet/redis/redis
        ├── Test "VulnerabilityReport cronjob/cleanup/cleanup"             version sha256:9155b03ee4d9
        │     service payments/CronJob/cleanup/cleanup
        └── Test "ExposedSecretReport deployment/api/api"                  version 1.8.0
              tags … report-kind:exposedsecretreport  app:payments
              service payments/Deployment/api/api
```

## Considered Options

- Product per cluster, engagement per namespace. Rejected: a namespace then has no own members or dashboard.
- Product Type per cluster. Rejected: every new cluster creates a Product Type, and the product name already keeps clusters apart.
- Product per codebase or environment (the first version). Rejected: it needs KubeRocketCI data (ADR 0001) and mixes namespaces of different clusters.

## Consequences

- The Product Type is a setting with the default `KubeRocketCI`, so a platform without KubeRocketCI sets its own name. All operators that write to one DefectDojo should use the same value, so that all namespace products are in one group. Changing the value later leaves the existing namespace products under the old Product Type, and their reimports fail until the products are moved.
- The cluster name is mandatory and must be unique per DefectDojo. Two clusters with the same name write into, and close, the same products.
- The CI pipeline writes codebase products under the same Product Type. A codebase name has no `/`, so the names never clash.
- The engagement name is fixed, because DefectDojo engagement names are not unique and a lookup takes the last one with the name.
- The test title has no namespace: the product already names it.
- Ownership is read from the product name prefix and the scan type, not from tags. DefectDojo has no product name prefix filter, so the operator filters by "contains" and checks the prefix itself.
