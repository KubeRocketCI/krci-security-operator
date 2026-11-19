<a name="unreleased"></a>
## [Unreleased]

### Features

- Close a test with one empty reimport
- Skip reports already uploaded after a restart
- Close tests only for gone workloads and containers
- Send the full reimport request with test tags
- Own and close tests by namespace product
- Write namespace products without KubeRocketCI input
- Skip a broken Trivy Operator report
- Send the service of a reimport request when set

### Bug Fixes

- Log a close only when the test has active findings
- Drop repeated report entries before the upload
- Version of a digest-only image is its digest
- Retry rejected reports and align names with the glossary

### Testing

- Make the cancelled reimport wait deterministic
- Model the DefectDojo reimport contract in the fake

### Routine

- Update current development version

### Documentation

- Describe the DefectDojo token options and 3.5.200 or later
- State that rootfs and filesystem modes skip CronJobs
- Test and recommend DefectDojo 3.5.200
- Target DefectDojo 3.5.200 only
- Pin upstream versions and slim the agent guide
- Clarify product tag repair and scale to zero
- Align ADRs with DefectDojo import behavior
- Add glossary, ADRs and agent skills config


<a name="v0.1.0"></a>
## v0.1.0 - 2026-11-17
### Features

- Import Trivy Operator reports of all namespaces into DefectDojo

### Bug Fixes

- Update golang.org/x/net to v0.62.0 and Go to 1.27.4
- Handle a partial report listing and a too short resync period

### Routine

- Pass the KubeRocketCI review: Sonar complexity and race tests
- Deploy only through the chart and test its rendering
- Add license and README

### Documentation

- Shorten the README and add a security model


[Unreleased]: https://github.com/KubeRocketCI/krci-security-operator/compare/v0.1.0...HEAD
