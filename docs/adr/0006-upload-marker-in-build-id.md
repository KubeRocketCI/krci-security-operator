# The upload marker lives in the build_id of the test

Each reimport writes an upload marker, `<report UID>:<resourceVersion>:<12 hex characters of a SHA-256 of the request>`, into the `build_id` of the runtime test. Before it uploads a report that no reimport of this process covers, the operator reads the tests of its product and skips the report when the marker equals the `build_id` of its test, so the first pass after a restart uploads only the reports that changed. The state lives in DefectDojo, next to the data it describes, and the operator still writes nothing to the cluster (ADR 0001).

## Considered Options

- Keep the skip in memory only. Rejected: every restart and every leader change reimported all reports, a burst of one request per report that held the DefectDojo workers for minutes.
- Annotate the Trivy report with the uploaded version. Rejected: it needs `patch` on both report kinds in every namespace and ends the read-only ClusterRole; the patch changes the `resourceVersion` it vouches for and wakes the controller again; Trivy Operator replaces the object on rescan; and the annotation records what the operator believes, not what DefectDojo holds, so a deleted test or a restored DefectDojo would never be filled again.
- Another field of the test. Rejected: `version` holds the image version, `branch_tag` is read by the portal as the branch of CI tests, `commit_hash` builds source links, and the test `description` cannot be set by a reimport.

## Consequences

- `build_id` is the one test field that a reimport writes, the tests list returns, and no consumer reads: not the portal, the CLI, the CI pipelines or the finding hash. DefectDojo shows it in the import history. A reimport that omits `build_id` stores an empty one.
- The marker holds the report version and a hash of what the request sends besides the report: the request format version, test title, service, version and tags. A changed request, such as a new version rule or another `app` tag, gives another marker, so the report is uploaded again.
- The request format version is a constant of the operator. It is bumped with every change to the payload rewrite, the `scan_date` rule or a constant field of the reimport form. The first pass after an operator upgrade that bumps it uploads every report once.
- The marker has at most 100 characters: a longer value is shortened with `trivy.Shorten`, in the same way on every pass, and is only compared, never parsed. DefectDojo accepts 150 characters and fails the save of the test above that, after the findings changed.
- DefectDojo saves the `build_id` of a new test before it reads the report and does not run a request in one transaction. A reimport that creates the test therefore sends no marker; the operator sets it with a `PATCH` of the test after the reimport returns. A reimport that fails or is interrupted after it created the test, and a failed `PATCH`, leave an empty `build_id`, so the report is uploaded again, and a rejection is logged and counted again after a restart. A reimport into a test that exists sends the marker: DefectDojo writes it after the findings, so a failed reimport leaves the earlier marker.
- A test exists for this purpose when a report was reimported into it in this process, or the tests read lists it: the test with the highest ID of its title in the last engagement named `trivy-operator`, which is the one a reimport writes into.
- A test is skipped only when its marker equals the one of the report; a test with another marker, an empty one (every test written before this decision) or none is uploaded. The first pass after the upgrade uploads every report once.
- The tests are read once per pass, before the first upload that needs them, and read again after a pass that uploaded; the close rules use the list. A read that fails fails the pass before its uploads. A Product Type or product that DefectDojo does not list is not a failure: the upload creates them.
- The in-memory record of a reimported report holds the marker, so a changed request is uploaded within a process as it is after a restart.
- A close clears the `build_id` of a test that has one with one `PATCH` of the test, before it mitigates the findings, so the unchanged report of a test that was closed is uploaded again when its workload or namespace returns. A close that is cut short leaves the marker cleared. A test without a `build_id` gets no `PATCH`.
- A reimport by hand into an operator test overwrites the marker; the operator uploads the report once more. Findings changed by hand in DefectDojo while the report is unchanged are not re-synced by a restart.
- A report version that DefectDojo rejected is not remembered across a restart and is uploaded once.
- A skipped test keeps its `target_end`, as it does today for an unchanged report within one process.
- Tests of the CI pipelines are in other products and are never read for markers.
