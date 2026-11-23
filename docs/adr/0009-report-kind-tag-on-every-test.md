# Every runtime test carries the tag of its report kind

Every reimport sends one tag of the report kind of its test, `report-kind:<kind>`, the report kind in lower case: `report-kind:vulnerabilityreport` on a VulnerabilityReport test and `report-kind:exposedsecretreport` on an ExposedSecretReport test. A consumer that splits vulnerabilities from exposed secrets filters the tests by this tag. The kind is also the first word of the test title (ADR 0002), but a title is a name, and no consumer parses a name. `report-kind` is a tag key the operator owns.

## Considered Options

- Read the first word of the test title. Rejected: it ties every consumer to the title format.
- One engagement per report kind. Rejected: the engagement is named after the source tool, one per integration (ADR 0002); a second one changes the layout that every existing test and lookup relies on.
- Tag the findings. Rejected: DefectDojo adds the tags of a reimport to findings and never removes them (ADR 0003).

## Consequences

- The values are the report kinds the operator imports, `vulnerabilityreport` and `exposedsecretreport`. A test the operator uploads has one `report-kind` tag, and a finding has none: filter findings by the tags of their test (`test__tags`).
- The tag is part of the reimport request, so it is part of the upload marker (ADR 0006). The first pass after an upgrade uploads every current report once, and the reimport replaces the tags of the test with the tags of the request (ADR 0003): the test carries the tag from then on, and a tag added by hand is removed. A test without a current report (closed, or not rescanned) is not reimported and has no `report-kind` tag until a report of it is uploaded. No manual step, no migration. The second pass uploads nothing.
