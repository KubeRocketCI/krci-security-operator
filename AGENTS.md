# krci-security-operator

Go operator (controller-runtime), one module per security integration; the Trivy module imports Trivy Operator reports into DefectDojo. No CRDs, `api/` types or webhooks. One instance per cluster, read-only cluster access.

- Before filing or reading an issue, or opening a PR: `docs/agents/issue-tracker.md`.
- Before triage or labeling: `docs/agents/triage-labels.md`.
- Before domain work: `GLOSSARY.md` (its terms go into code names, logs and notes), then the ADRs of the area in `docs/adr/` (`docs/agents/domain.md`).
- Before changing reconcile, watches, closing or error handling: the module rules in `docs/development.md#rules-for-a-module`, then the behavior in `docs/trivy.md`.
- Before writing or reviewing Go code: `docs/development.md#code-rules`.
- DefectDojo or Trivy Operator behavior (reimport rules, parser, report labels, the fake DefectDojo): `docs/development.md#upstream-sources`, checked in the upstream source at the supported versions. DefectDojo 3.5.200 or later is supported (ADR 0007); earlier versions may work but are not tested.
- The fake DefectDojo follows the fixtures recorded on a live DefectDojo, not a reading of the source: a change to it or to a client call goes with its scenario in `internal/ddcontract` and `make defectdojo-record` (`docs/development.md#defectdojo-contract`).

## Design

- The operator reads only Kubernetes and Trivy Operator objects. No KubeRocketCI resource or label is read, and no KubeRocketCI name is written, except the default Product Type `KubeRocketCI` (ADR 0001).
- Every report of every namespace goes to the product `<cluster name>/<namespace>` under the Product Type setting, engagement `trivy-operator`, test `<ReportKind> <kind>/<name>/<container>` (ADR 0002). The layout is a contract other systems read: change it only with its ADR.
- The cluster name has no default: the operator does not start and the chart does not render without it.
- The only namespace filter is `excludeNamespaces`. There are no scopes, scope switches or platform product.
- A Namespace label becomes a tag only for a key the installer lists in `namespaceLabelTags`; the operator names no label itself, and the prefix `k8s-ns-label.` of the product tags is its own (ADR 0009).

## Generated files

Edit the source: `deploy-templates/README.md` comes from `README.md.gotmpl` and the `# --` comments of `values.yaml` (`make helm-docs`); `CHANGELOG.md` comes from `make changelog`.

## RBAC

RBAC has no markers. A new read through the API reader needs its verb in `deploy-templates/templates/role.yaml` and in the access table of `docs/trivy.md`; the ClusterRole stays read-only.

## New configuration value

1. The variable in `internal/controller/trivy/config.go`, with a test.
2. The env entry in `deploy-templates/templates/deployment.yaml`.
3. Its name in `envNames` of `test/deploy/render_test.go`.
4. The `# --` documented key in `deploy-templates/values.yaml`, then `make helm-docs`.
5. The configuration table of `docs/trivy.md`.

## Checks

`make help` lists the targets; `docs/development.md#checks` lists what CI runs. `make test` runs the chart render tests only when helm is installed. One test: `go test ./internal/controller/trivy/ -run TestName -v`. A function over the gocognit limit of 15 is split into helpers; the limit is never suppressed with `//nolint`.

## Logging

Kubernetes message style: capital first letter, no trailing period, past tense, the object type named, balanced key-value pairs (`"Could not import report"`).

## Commits

Subject `EPMDEDP-<id>: <type>: <subject>`, 10 to 85 characters, type one of fix, feat, docs, style, refactor, test, chore; CI checks it.
