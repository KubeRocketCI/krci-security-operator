# A missing report is not clean

The operator closes a runtime test only when its stable workload is gone, its container is no longer in the pod template, or its namespace is gone or excluded. A missing report never closes a test. Trivy Operator deletes a VulnerabilityReport on TTL expiry (24 h by default) and writes it again after the next scan, skips images it excludes, and keeps the old report after a failed scan, so the absence of a report means "not scanned". An empty report means "clean", and its reimport closes the findings through DefectDojo.

## Considered Options

- Close a test when no current report is listed (the first version). Rejected: every TTL rescan closed and then reactivated all findings of the workload.
- Close after a grace period. Rejected: a timer adds state and still closes findings that are only unscanned.

## Consequences

- A container whose image Trivy Operator excludes keeps its last test open.
- A workload scaled to zero is not gone: its tests stay open until the workload is deleted.
- A broken report (`GLOSSARY.md`) is never uploaded, because DefectDojo would read it as empty and close every finding of the test. A report is broken when it has no resource kind or name, no `report` block, or no result list (`report.vulnerabilities` for a VulnerabilityReport, `report.secrets` for an ExposedSecretReport). Trivy Operator always writes the list, also when it is empty.
- A failed upload gives the operator no right to close that test; the result in DefectDojo is unknown (DefectDojo does not apply a reimport as one transaction), so the operator retries the upload. The other tests of the namespace are still closed by these rules.
