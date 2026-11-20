# Development

## Layout

| Path | Contents |
|---|---|
| `cmd/main.go` | manager setup: metrics, health probes, leader election; loads the module configuration and registers the module |
| `cmd/ddcontract/` | runs the DefectDojo contract scenarios against a live DefectDojo: records or verifies the fixtures |
| `internal/controller/trivy/` | the Trivy module: `Config` (environment parsing and validation), `SetupWithManager` (controller and sweeper), `Reconciler` (pass over a namespace), namespace exclusion, closing, event mapping |
| `internal/ddcontract/` | the DefectDojo contract scenarios, their runner and outcome, and the fixtures recorded on a live DefectDojo (`fixtures/`) |
| `pkg/defectdojo/` | minimal DefectDojo API v2 client with one lock per test for the reimport and the close |
| `pkg/trivy/` | Trivy report parsing, image and workload resolution, paged listing, the namespace product, engagement, test title, tags and ownership, component tag |
| `deploy-templates/` | Helm chart, the only deployment artifact |
| `test/deploy/` | chart render tests: `helm template` checked against the configuration the code reads and the read-only access |
| `ct-configs/` | chart-testing configuration used by CI |

## Rules for a module

- A module lives in its own package under `internal/controller/` and exposes `Config`, `LoadConfig` and `SetupWithManager`.
- The module reads its configuration from environment variables that the chart sets from its values. `cmd/main.go` only loads and passes it on.
- The operator reads Kubernetes objects and the Trivy reports (as unstructured objects) only: no KubeRocketCI resource or label (ADR 0001), so the repository depends on no other KubeRocketCI operator module.
- A module returns a transient error from `Reconcile` with a zero `Result` (controller-runtime ignores the `Result` of an error); with a nil error it requeues only through `Result.RequeueAfter` (the resync, an absent optional dependency), never through `Result.Requeue`.
- Background work that must change state wakes the controller through a channel source instead of acting itself, so the workqueue serializes it per key.
- A module watches the metadata of large objects only and reads everything else through the API reader, so big objects never sit in the cache.
- A module reads the body of a large object only when its metadata does not decide: the Trivy module lists report metadata, from the cache for a kind watched at start, and reads a report body once per report version and for an upload; it keeps the facts of a report version in memory, pruned at the end of every pass to the versions of the kinds it listed completely. A pass holds at most two report bodies. It keeps the report metadata of the namespace, the container names, image references and components of the workloads, and the test IDs and titles of the namespace for one pass. Every list through the API reader goes through `trivy.ListPages`, 500 objects per page: a continue token that expired (HTTP 410) restarts the listing, at most 3 times, then the pass fails. A kind of reports is listed completely before any of its reports is decided.
- The ClusterRole stays read-only and lists exactly what the code calls. A new module that needs more access adds its rules to `deploy-templates/templates/role.yaml` and to the access table of [trivy.md](trivy.md#access); `test/deploy` fails on a write verb in the ClusterRole.

## Code rules

Checked in review. `make lint` checks formatting, line length, complexity, whitespace, unused code and shadowed predeclared identifiers (`.golangci.yaml`); test tooling is `internal/ddcontract` and `cmd/ddcontract`.

Comments and names:

- A body comment states a constraint, default, limit, unit, order or upstream fact the code does not show, in present tense; one that restates the code or narrates history is deleted. A doc comment starts with its name; a const-block group comment is exempt. An unexported symbol has a doc comment only when it adds such a fact.
- A DefectDojo or Trivy Operator behavior the code relies on has a row in [Upstream sources](#upstream-sources) or a scenario in `internal/ddcontract`; a change that relies on a new one adds the row or the scenario.
- In production code a value with one meaning is declared once; another package uses the exported constant. Test tooling keeps its own values, independent of the code it checks.

Errors and context:

- An error is wrapped with `%w` where the function adds the action or an object the callee does not name (kind, report, test or finding ID, product); a `Reconcile` path does not add the namespace, controller-runtime logs the request. An error without a cause is `errors.New`, or `fmt.Errorf` without `%w` when it formats values; an error callers match is an exported sentinel checked with `errors.Is`.
- A returned error is not also logged.
- A function that returns a non-nil error returns zero values for its other results, unless its doc comment says what they hold.
- Production code passes on the ctx it received; `context.Background()` appears only in `cmd/*/main.go`.
- A loop that collects per-item errors returns at once when `ctx.Err() != nil`.

Controller:

- A `Reconciler` field shared across passes is accessed only under its mutex: `r.mu` for the in-memory state, `credMu` for the credentials. State of one pass lives in `pass`.
- In `internal/controller`, time and randomness come from `r.now` and `r.random`.
- Output that leaves the process (a request, tags, a logged list, a fixture) and is built from a map has a fixed order; a returned slice in map order says so in its doc comment.

Tests:

- An expected value is a literal, a recorded fixture or an invariant between two outputs; never the output of the code under test or a copy of its logic.
- A new check or comparison has a test that fails when the check is removed or inverted.
- A test that changes a fixture step finds the step by name or asserts its name first.

## The Trivy module

| File | Contents |
|---|---|
| `trivy.go` | `SetupWithManager`: the controller keyed by namespace, the metadata watches of the reports, the Namespace watch, the sweeper |
| `config.go` | `Config`, its environment variables, defaults and validation |
| `reconciler.go` | `Reconcile`, the credentials Secret and its cache, the pass over a namespace, the decision on a report and the choice of the report of a test, the reimport of a report, and the in-memory state: reimported report versions, rejected report versions, facts of report versions, closed tests, released namespaces |
| `report_list.go` | the report metadata of a pass: the listing of a kind from the cache or the API reader, the records by kind and name, the worklist in name order, the index of the reports by resource and container, and `adopt` of a read that returned another version or found the report gone |
| `report_body.go` | `reportBodies`: the read of a report body, compared with the requested report version, and the facts of a report version (image, broken body) |
| `workload_report.go` | the report on the stable workload itself: the check that it can be uploaded before the report of a ReplicaSet or Job is |
| `namespace.go` | the live namespace, `excludeNamespaces` and the tags of the listed namespace labels |
| `closing.go` | the namespace product lookup and the tests list of a pass (read before the first upload that no reimport of the process covers, and again after a pass that uploaded; the close rules use it), closing of stale and released tests, product tags; the sweeper that wakes namespaces for the controller |
| `watch.go` | mapping of report events to namespaces |

The unit tests use the fake client and a fake DefectDojo (`defectdojo_fake_test.go`) that models the DefectDojo reimport contract; `defectdojo_fake_contract_test.go` has one test per rule, and `defectdojo_fake_replay_test.go` checks the fake against the recorded DefectDojo answers ([DefectDojo contract](#defectdojo-contract)). There is no envtest suite. The event wiring in `SetupWithManager` is not unit-tested; the kind testbed covers it.

## DefectDojo contract

`internal/ddcontract` holds scenarios: steps over the client calls of the operator (reimport into a new and an existing test, repeated entries, `build_id`, a failing first reimport, the empty reimport of a close and the close of one finding, the products, engagements, tests and findings lists, the product and test `PATCH`) and the triage a DefectDojo user does. After each step the outcome is read: the result of the call, and the products of the run with their engagements, tests (title, version, `build_id`, tags), findings (hash code, service, active, mitigated, triage flags) and import history actions. IDs become ordinals in the order they appear; titles are case-folded, as DefectDojo hashes them.

`internal/ddcontract/fixtures/<scenario>.json` holds the outcome of every step recorded on DefectDojo 3.5.200 with deduplication off (the default), and the HTTP requests of the client with the answers. The token, the host and the run name are not stored; email addresses are replaced. A failed call is compared by its HTTP status and the form fields its body names.

- `make test` replays every scenario on the fake DefectDojo and fails on a difference from the fixture (`TestFakeDefectDojo_ReplaysTheRecordedScenarios`).
- `make test` also replays every scenario through the operator client against the recorded answers and fails when a request differs from the recorded one (`TestReplayRequests_TheClientSendsTheRecordedRequests`): method, path and query with IDs as `{id}`, form fields in order, the report, and JSON bodies with timestamps as `{time}`. A change of a client request needs `make defectdojo-record`.
- `make defectdojo-verify` runs the scenarios on a live DefectDojo and lists every difference from the fixtures. `make defectdojo-record` writes the fixtures again.
- Both need `DEFECTDOJO_URL` and `DEFECTDOJO_TOKEN` of a user that may create and delete product types; `SCENARIOS` limits the run. Both stop on a DefectDojo with `enable_deduplication` on, which the fake does not model; any version is accepted, and the version is read from `info.version` of `/api/v2/oa3/schema/`. Verify prints a note when the fixture was recorded on another version. Each scenario runs under its own product type `ddcontract-<random>`, deleted afterwards; `go run ./cmd/ddcontract -keep` keeps it for inspection, `-dir` writes or reads another fixtures directory. The try-kuberocketci testbed: the URL and the token are in the Secret `krci-security/defectdojo-credentials`.

Run `make defectdojo-verify`:

- before a release;
- when the supported DefectDojo version changes: on the new version, then `make defectdojo-record`, `make test`, and the fake, this page and ADR 0007 follow the differences;
- when a scenario is added or changed: `make defectdojo-record`, then `make test`.

A change of the client calls (`pkg/defectdojo`) or of the fake adds or changes the scenario of the call.

## Upstream sources

The operator depends on DefectDojo and Trivy Operator behavior that no API document states. Check it in the upstream source at the supported versions, not from memory. DefectDojo 3.5.200 or later is supported (ADR 0007); earlier versions may work but are not tested.

| Project | Supported | Contract unchanged across |
|---|---|---|
| DefectDojo | 3.5.200 or later, verified with 3.5.200 (see [trivy.md](trivy.md#defectdojo-requirements)) | 3.5.200 |
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
| `dojo/test/models.py` | `Test.title` (255 characters), `Test.version` (100 characters), `Test.build_id` (150 characters; the operator keeps it within 100, [ADR 0006](adr/0006-upload-marker-in-build-id.md)); `Test_Import` and `Test_Import_Finding_Action`: the import history, one entry per completed import or reimport, actions created, closed, reactivated, untouched |
| `dojo/test/api/serializer.py` | `TestSerializer`: the tests list returns every model field, `build_id` included; a `PATCH` of `build_id` sets the upload marker of a new test and clears it on a close |
| `dojo/validators.py` | `TAG_PATTERN`: a tag has no space, comma or quote |
| `dojo/db_migrations/0066_django_tagulous.py` | tag `name` column (255 characters) |
| `dojo/importers/default_importer.py` | the import that creates a test: one finding per entry in report order, no matching; `create_test` saves the title, version, `build_id` and tags before the report is parsed |
| `dojo/importers/default_reimporter.py` | `get_original_findings` (close set by service, findings of the test that are or are not active), `process_matched_finding` (reactivation, kept triage states), `close_old_findings` (an empty report mitigates the close set: [How a test is closed](trivy.md#how-a-test-is-closed)); candidates of a hash in ascending ID, the first one matched for every entry of the hash; the entries are sorted by hash code first (`dojo/finding/deduplication.py` `deduplication_ordering_key`), so the findings one reimport creates get their IDs in hash code order |
| `dojo/importers/base_importer.py` | `update_test_meta` (version and `build_id`: an omitted field is stored as empty), `update_test_tags` (only a non-empty list is written), `mitigate_finding` (risk acceptance removed, a note per finding) |
| `dojo/models.py` | statistics of a test: `statistics.after.total.active` counts the active findings of the whole test, every service |
| `dojo/authorization/api_permissions.py` `UserHasReimportPermission` | a reimport by `test` ID needs the import permission on the test; an unknown test gives 400 |
| `dojo/finding/api/views.py`, `dojo/finding/helper.py` | `findings/<id>/close/`, the one-by-one close: sets the mitigation time to the request time and only active findings are read |
| `dojo/importers/auto_create_context.py` | product type conflict, last engagement and test by name |
| `dojo/api_v2/serializers.py` | `ReImportScanSerializer`: form validation (no string field has a `max_length`, a value over its column fails the save with 500; a value may not be blank), context and test created before the parser runs, a new test with its `build_id`, the import that creates a test runs with `close_old_findings` off; `TagListSerializerField`: a value is split at commas and unpaired double quotes |
| `dojo/finding/helper.py` `update_finding_status` | setting `false_p` or `out_of_scope` also mitigates the finding |
| `dojo/product/api/filters.py` `ApiProductFilter` | `name_exact`, an `iexact` match on the product name: the product lookup by exact name uses it |
| `dojo/authorization/api_permissions.py` `check_auto_create_permission` | permissions of a reimport that creates the Product Type, product and engagement |
| `dojo/authorization/authorization.py`, `roles_permissions.py` | staff, superuser and `authorized_users` only; role assignments are not read |

Confirmed on a DefectDojo 3.5.200 testbed (`build_id`):

- A reimport with `build_id` stores it, and `GET /api/v2/tests/` returns it.
- A reimport without `build_id` writes `""`.
- Up to 150 characters are accepted; 151 characters give HTTP 500.
- `PATCH /api/v2/tests/<id>/` with `{"build_id":""}` is accepted and clears it.

Confirmed on a DefectDojo 3.5.200 testbed (tags, scenarios `form-validation` and `product-tags`):

- A reimport stores the tags of a test in lower case: `K8s-Workload:Deployment/App` becomes `k8s-workload:deployment/app`.
- `PATCH /api/v2/products/<id>/` stores a product tag as sent: `Owner:Team` stays.
- A tag over 255 characters fails the save of the test with HTTP 500, and a tag with a space or a single quote gives 400.

Confirmed on a DefectDojo 3.5.200 testbed (the close with a reimport of an empty report):

- `POST /api/v2/reimport-scan/` with `test=<id>`, `scan_type=Trivy Operator Scan`, `service`, `close_old_findings=true`, the current `version` and a Trivy Operator report whose result list is empty answers 201 with `statistics.after.total.active` of `0`, and mitigates every finding of the service that is not mitigated, active or not: 73 findings in 0.46 s, 1,736 in 10.0 s.
- False positive and out of scope flags are kept, the risk acceptance is removed, and the import history holds one reimport entry with the number of findings closed.
- The test `version` is kept when sent and written empty when omitted; an omitted `build_id` is written empty.
- Findings of another service in the same test stay active: `dojo/importers/default_reimporter.py` filters the close set by `service` (or by none when it is omitted), and the upstream `unittests/test_import_reimport.py` closes service A, then B. The operator reads `statistics.after.total.active` and repeats the close for the next service.

Trivy Operator files: `pkg/trivyoperator/constants.go` (report labels), `pkg/apis/aquasecurity/v1alpha1/` (report types, `report-ttl` annotation).

## Checks

```bash
make test           # fmt, vet, unit tests with the race detector (needs gcc), and the chart render tests when helm is installed
make lint           # golangci-lint; gocognit fails a function above cognitive complexity 15, the Sonar go:S3776 limit of the quality gate
make validate-docs  # chart README is current
helm lint deploy-templates
```

`helm lint` without `clusterName` passes with the warning `missing required values`; `helm template` fails. CI runs the same checks with helm installed, plus `ct lint`, hadolint and CodeQL, and checks the commit message format (`AGENTS.md#commits`).
