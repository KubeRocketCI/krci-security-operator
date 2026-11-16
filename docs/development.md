# Development

## Layout

| Path | Contents |
|---|---|
| `cmd/main.go` | manager setup: metrics, health probes, leader election; loads the module configuration and registers the module |
| `internal/controller/trivy/` | the Trivy module: `Config` (environment parsing and validation), `SetupWithManager` (controller and sweeper), `Reconciler` (pass over a namespace), classification, closing, event mapping |
| `pkg/defectdojo/` | minimal DefectDojo API v2 client with a per-test import lock |
| `pkg/trivy/` | Trivy report parsing, image and workload resolution, DefectDojo names, tags and ownership per scope, component tag |
| `deploy-templates/` | Helm chart, the only deployment artifact |
| `test/deploy/` | chart render tests: `helm template` checked against the configuration the code reads and the read-only access |
| `ct-configs/` | chart-testing configuration used by CI |

## Rules for a module

- A module lives in its own package under `internal/controller/` and exposes `Config`, `LoadConfig` and `SetupWithManager`.
- The module reads its configuration from environment variables that the chart sets from its values. `cmd/main.go` only loads and passes it on.
- The operator reads `Stage` and `CodebaseImageStream` (`v2.edp.epam.com`) and the Trivy reports as unstructured objects, so the repository depends on no other KubeRocketCI operator module.
- A module returns transient errors from `Reconcile`; only an absent optional dependency requeues with a nil error.
- Background work that must change state wakes the controller through a channel source instead of acting itself, so the workqueue serializes it per key.
- A module watches the metadata of large objects only and reads everything else through the API reader, so big objects never sit in the cache.
- The ClusterRole stays read-only and lists exactly what the code calls. A new module that needs more access adds its rules to `deploy-templates/templates/role.yaml` and to the access table of [trivy.md](trivy.md#access); `test/deploy` fails on a write verb in the ClusterRole.

## The Trivy module

| File | Contents |
|---|---|
| `trivy.go` | `SetupWithManager`: the controller keyed by namespace, the metadata watches of the reports, the Namespace and Stage watches, the sweeper |
| `reconciler.go` | `Reconcile`, the import of a namespace, the in-memory state of imported reports |
| `classify.go` | the scope of a namespace: Stage matching, tenant label, `excludeNamespaces`, scope switches |
| `closing.go` | closing of stale and released tests; the sweeper that wakes namespaces for the controller |
| `watch.go` | mapping of report and Stage events to namespaces |

The unit tests use the fake client and a fake DefectDojo. The event wiring in `SetupWithManager` is not unit-tested; the kind testbed covers it.

## Checks

```bash
make test           # fmt, vet, unit tests with the race detector (needs gcc), and the chart render tests when helm is installed
make lint           # golangci-lint; gocognit fails a function above cognitive complexity 15, the Sonar go:S3776 limit of the quality gate
make validate-docs  # chart README is current
helm lint deploy-templates
```

CI runs the same checks with helm installed, plus `ct lint`, hadolint and CodeQL, and checks the commit message format `EPMDEDP-<id>: <type>: <subject>`.
