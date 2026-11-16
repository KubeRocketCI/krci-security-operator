# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go operator that hosts the in-house security integrations of a KubeRocketCI cluster as modules. The first module (`internal/controller/trivy`) imports Trivy Operator `VulnerabilityReport` and `ExposedSecretReport` objects into the cluster's DefectDojo. It has no CRDs and no webhooks.

**Read `AGENTS.md` first** - it covers the project structure, the files you must not edit, and the design rules. This file adds the commands and the control flow.

## Commands

```bash
make build         # Linux binary to dist/manager-$(GOARCH); the Dockerfile only packages it
make test          # fmt, vet, unit tests with coverage
make lint-fix      # golangci-lint with auto-fix
make helm-docs     # after changing deploy-templates/values.yaml or README.md.gotmpl
make validate-docs # CI gate: fails when deploy-templates/README.md is stale
make run           # run the manager locally against the current kubeconfig
```

Run a single test:

```bash
go test ./internal/controller/trivy/ -run TestName -v
```

## Architecture

1. `cmd/main.go` builds the manager (metrics, probes, leader election), loads the Trivy module configuration from the environment (`trivy.LoadConfigFromEnv`) and calls `trivy.SetupWithManager`. An invalid configuration stops the process at start.
2. `internal/controller/trivy` is the module. `config.go` holds `Config`, its defaults and validation. `trivy.go` builds the controller (Namespaces, Stages, report metadata) and the sweeper. `reconciler.go` is the pass over a namespace, `classify.go` decides its scope, `closing.go` closes tests and runs the sweeper, `watch.go` maps events to namespaces.
3. `pkg/trivy` turns a Trivy report into a DefectDojo import: it resolves the image and the stable workload of a report, derives the component tag, and builds the names, tags and test title per scope.
4. `pkg/defectdojo` is the API client. Imports into one test are serialized by its per-test lock.

The reconcile key is a namespace. Its scope (stage, tenant, platform) is decided on every pass, and the scope switches and `excludeNamespaces` decide whether it is imported. A pass imports the changed reports, then closes the owned tests of the namespace that it did not import. A namespace that is gone or out of scope has its owned tests closed once in `Reconcile`; the sweeper only wakes such namespaces at start and every 6h (through the controller's channel source) and closes nothing itself. Transient failures are returned so the workqueue backs off; only an absent Secret or report CRD requeues with a nil error. Reports are listed in small pages and imported page by page. Reports are watched by metadata only; full reports and workloads are read through the API reader.

## Generated-file gotchas

`deploy-templates/README.md` is generated from `README.md.gotmpl` and the `# --` comments of `values.yaml` by helm-docs. CI enforces freshness with `make validate-docs`. RBAC has no generator: edit `deploy-templates/templates/role.yaml` and `config/rbac/role.yaml` together.
