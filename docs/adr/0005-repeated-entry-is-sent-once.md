# A repeated entry is sent once

The payload of a report keeps the first of its repeated entries and drops the others (`GLOSSARY.md`). A report can hold entries that DefectDojo gives the same hash code (title, severity, vulnerability ids, description, service). DefectDojo creates a finding per entry on the upload that creates a test, and matches every entry of one hash code to the lowest-ID finding on a reimport, so the other finding is left in the close set and is closed while the report still holds it.

## Considered Options

- Accept and document. Rejected: from the second reimport on, a finding that the report holds is closed, and the test shows more findings than issues.
- Set the DefectDojo system setting `enable_deduplication=true`. Rejected: the second finding is created inactive as a duplicate and the reimport still closes it; the setting is global to a DefectDojo that other producers use.
- Collapse in the payload. Chosen: the operator is the only place that knows the report before DefectDojo parses it.

## Consequences

- The key of an entry is the hash input of its finding as the DefectDojo 3.5.200 Trivy Operator parser builds it: an absent field is the parser default, a null field is `None`, case is ignored. `docs/trivy.md` lists the fields and the cases where the key is stricter than the hash. Another DefectDojo version that builds or hashes other fields needs the key changed with it.
- The fields of a dropped entry that are not in the key (`score`) are not sent.
- Two occurrences of one secret rule in one target with the same match are one finding.
- The first reimport after an upgrade closes the duplicate findings of tests that were uploaded before the change.
- The key assumes `HASHCODE_FIELDS_PER_SCANNER` of `Trivy Operator Scan` at its default and `enable_deduplication=false`.
