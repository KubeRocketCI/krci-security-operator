# Development

## Layout

| Path | Contents |
|---|---|
| `cmd/main.go` | manager setup: metrics, health probes, leader election; loads the module configuration and registers the module |
| `internal/controller/trivy/` | the Trivy module: `Config` (environment parsing and validation), `SetupWithManager` (controller and sweeper), `Reconciler` (pass over a namespace), namespace exclusion, closing, event mapping |
| `pkg/defectdojo/` | minimal DefectDojo API v2 client with one lock per test for the reimport and the close |
| `pkg/trivy/` | Trivy report parsing, image and workload resolution, paged listing, the namespace product, engagement, test title, tags and ownership, component tag |
| `deploy-templates/` | Helm chart, the only deployment artifact |
| `test/deploy/` | chart render tests: `helm template` checked against the configuration the code reads and the read-only access |
| `ct-configs/` | chart-testing configuration used by CI |

## Rules for a module

- A module lives in its own package under `internal/controller/` and exposes `Config`, `LoadConfig` and `SetupWithManager`.
- The module reads its configuration from environment variables that the chart sets from its values. `cmd/main.go` only loads and passes it on.
- The operator reads Kubernetes objects and the Trivy reports (as unstructured objects) only: no KubeRocketCI resource or label (ADR 0001), so the repository depends on no other KubeRocketCI operator module.
- A module returns transient errors from `Reconcile`; only an absent optional dependency requeues with a nil error.
- Background work that must change state wakes the controller through a channel source instead of acting itself, so the workqueue serializes it per key.
- A module watches the metadata of large objects only and reads everything else through the API reader, so big objects never sit in the cache.
- A module lists large objects in pages and finishes each page before it reads the next. Across pages it keeps the report metadata index of one kind and the container names of the workloads for one pass, bounded by pages of 500 objects, and the test IDs and titles of the namespace. Every list goes through `trivy.ListPages`: a continue token that expired (HTTP 410) restarts the listing, at most 3 times, then the pass fails.
- The ClusterRole stays read-only and lists exactly what the code calls. A new module that needs more access adds its rules to `deploy-templates/templates/role.yaml` and to the access table of [trivy.md](trivy.md#access); `test/deploy` fails on a write verb in the ClusterRole.

## The Trivy module

| File | Contents |
|---|---|
| `trivy.go` | `SetupWithManager`: the controller keyed by namespace, the metadata watches of the reports, the Namespace watch, the sweeper |
| `config.go` | `Config`, its environment variables, defaults and validation |
| `reconciler.go` | `Reconcile`, the credentials Secret and its cache, the pass over a namespace, the choice of the report of a test, the reimport of a report, and the in-memory state: reimported report versions, rejected report versions, closed tests, released namespaces |
| `workload_report.go` | the report on the stable workload itself: the metadata index of the reports of a kind, and the check that it can be uploaded before the report of a ReplicaSet or Job is |
| `namespace.go` | the live namespace and `excludeNamespaces` |
| `closing.go` | the namespace product lookup, closing of stale and released tests, product tags; the sweeper that wakes namespaces for the controller |
| `watch.go` | mapping of report events to namespaces |

The unit tests use the fake client and a fake DefectDojo (`defectdojo_fake_test.go`) that models the DefectDojo reimport contract; `defectdojo_fake_contract_test.go` has one test per rule. There is no envtest suite. The event wiring in `SetupWithManager` is not unit-tested; the kind testbed covers it.

## Upstream sources

The operator depends on DefectDojo and Trivy Operator behavior that no API document states. Check it in the upstream source at the supported versions, not from memory.

| Project | Supported | Contract unchanged across |
|---|---|---|
| DefectDojo | 3.5.200 (see [trivy.md](trivy.md#defectdojo-requirements)) | 3.5.200 |
| Trivy Operator | 0.34.0 or later, verified with 0.36.1 | 0.34.0 to 0.36.1 |

Trivy Operator: supported means the releases of the last three months. On a new Trivy Operator release, compare the files below between the old and the new tag, update the fake and this table, and move the lower bound.

```bash
git clone --filter=blob:none https://github.com/defectdojo/django-defectdojo "$TMPDIR/django-defectdojo"
git clone --filter=blob:none https://github.com/aquasecurity/trivy-operator "$TMPDIR/trivy-operator"
git -C "$TMPDIR/django-defectdojo" checkout 3.5.200
git -C "$TMPDIR/trivy-operator" checkout v0.36.1
```

DefectDojo files that define the reimport contract:

| File | Rule |
|---|---|
| `dojo/tools/trivy_operator/` | parser: title, severity, vulnerability ids, description and service of each finding; a report without labels or result list gives no findings |
| `dojo/settings/settings.dist.py` | `HASHCODE_FIELDS_PER_SCANNER["Trivy Operator Scan"]`, `HASH_CODE_FIELDS_ALWAYS` (service) |
| `dojo/finding/models.py` | `hash_fields`, `get_vulnerability_ids`: how the hash is built; `Finding.service` (200 characters) |
| `dojo/test/models.py` | `Test.title` (255 characters), `Test.version` (100 characters) |
| `dojo/validators.py` | `TAG_PATTERN`: a tag has no space, comma or quote |
| `dojo/db_migrations/0066_django_tagulous.py` | tag `name` column (255 characters) |
| `dojo/importers/default_reimporter.py` | `get_original_findings` (close set by service), `process_matched_finding` (reactivation, kept triage states), `close_old_findings` |
| `dojo/importers/base_importer.py` | `update_test_meta` (version), `update_test_tags`, `mitigate_finding` (risk acceptance removed) |
| `dojo/importers/auto_create_context.py` | product type conflict, last engagement and test by name |
| `dojo/api_v2/serializers.py` | `ReImportScanSerializer`: form validation, context and test created before the parser runs |
| `dojo/product/api/filters.py` `ApiProductFilter` | `name_exact`, an `iexact` match on the product name: the product lookup by exact name uses it |
| `dojo/authorization/api_permissions.py` `check_auto_create_permission` | permissions of a reimport that creates the Product Type, product and engagement |
| `dojo/authorization/authorization.py`, `roles_permissions.py` | staff, superuser and `authorized_users` only; role assignments are not read |

Trivy Operator files: `pkg/trivyoperator/constants.go` (report labels), `pkg/apis/aquasecurity/v1alpha1/` (report types, `report-ttl` annotation).

## Checks

```bash
make test           # fmt, vet, unit tests with the race detector (needs gcc), and the chart render tests when helm is installed
make lint           # golangci-lint; gocognit fails a function above cognitive complexity 15, the Sonar go:S3776 limit of the quality gate
make validate-docs  # chart README is current
helm lint deploy-templates
```

`helm lint` without `clusterName` passes with the warning `missing required values`; `helm template` fails. CI runs the same checks with helm installed, plus `ct lint`, hadolint and CodeQL, and checks the commit message format (`AGENTS.md#commits`).
