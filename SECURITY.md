# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The KubeRocketCI team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

To report a security vulnerability, please follow these steps:

1. **DO NOT** disclose the vulnerability publicly on GitHub Issues or other public forums.
2. Email us at <SupportEPMD-EDP@epam.com> with a detailed description of the vulnerability.
3. Include steps to reproduce, impact, and any potential mitigations if known.
4. Allow time for the team to investigate and address the vulnerability before any public disclosure.

## What to expect

- Acknowledgment of your report within 48 hours
- An initial assessment of the report within 7 days
- Regular updates about the progress of addressing the vulnerability
- Credit for discovering the vulnerability (unless you prefer to remain anonymous)

## Disclosure Policy

We follow a coordinated disclosure process:

1. Once a vulnerability is confirmed, we develop and test a fix
2. We prepare a security advisory to accompany the fix
3. We release the fix and publish the security advisory simultaneously
4. After the fix has been available for 10 days, details may be discussed publicly

## Security Model

| Surface | Reachable from | Protection |
|---|---|---|
| Kubernetes API | the operator | read-only ClusterRole for reports, namespaces, Stages, `CodebaseImageStream`s and workloads ([access table](docs/trivy.md#access)); in its own namespace, `get` on the one named credentials Secret, its Lease and `create` on events |
| DefectDojo credentials | the operator namespace | a Secret with `url` and `token`, read without a cache at most once a minute; the token goes only into the `Authorization` header of requests to that `url`. Keep tenants out of this namespace |
| DefectDojo API | the operator | writes only `reimport-scan` and the closing of findings, and closes findings only in tests tagged with its own cluster |
| Stages and workloads | tenants | a `Stage` counts only for a namespace whose `app.edp.epam.com/tenant` label equals the Stage's namespace; workload labels and annotations only feed the lower-cased `krci-component` tag |
| Health probes | the pod IP | `:8081`; the chart creates no Service and serves no metrics |
| Pod | | distroless static image, non-root user 65532, read-only root filesystem, no capabilities, no privilege escalation, seccomp `RuntimeDefault` |

Thank you for helping us keep our project and our users secure!
