# Contributing

Thanks for helping with the KubeRocketCI Security Operator. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Issues

Search the [issues](https://github.com/KubeRocketCI/krci-security-operator/issues) first, then use a template. A bug report names the operator, Kubernetes, Trivy Operator and DefectDojo versions, the steps, and the expected and actual result.

Never report a vulnerability in an issue: see [SECURITY.md](SECURITY.md).

## Pull requests

1. One pull request, one commit, branched from `main`.
2. Run the checks of CI: `make lint test validate-docs`. After a change of `deploy-templates/values.yaml` or `README.md.gotmpl`, run `make helm-docs` first.
3. Write the commit title as `EPMDEDP-<ID>: <type>: <Subject>`, at most 85 characters, with the type `feat`, `fix`, `docs`, `style`, `refactor`, `test` or `chore`, and `!` after it for a breaking change.
4. Fill in the pull request template.

The code layout and the rules for a module are in [docs/development.md](docs/development.md).
