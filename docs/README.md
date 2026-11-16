# krci-security-operator documentation

The operator runs the security integrations of a KubeRocketCI cluster. Each integration is a module under `internal/controller/<module>` that is configured and switched on by itself.

## Where to go

| Document | Read it when you want to |
|---|---|
| [../README.md](../README.md) | see what the operator does and install it |
| [trivy.md](trivy.md) | learn how the Trivy module classifies namespaces, names DefectDojo objects, closes tests and handles errors |
| [../deploy-templates/README.md](../deploy-templates/README.md) | look up the chart values (generated) |
| [development.md](development.md) | find your way around the code and add a module |

## Modules

| Module | State | What it does |
|---|---|---|
| `trivy` | first version | imports Trivy Operator `VulnerabilityReport` and `ExposedSecretReport` into DefectDojo |

Planned, not in this version:

- ConfigAudit and RBAC reports of Trivy into DefectDojo;
- runtime SBOMs into Dependency-Track;
- image signature and attestation checks against Tekton Chains;
- `PolicyReport` from Kyverno or Gatekeeper.
