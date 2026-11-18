# Every reimport sends the service, the version and all tags

Each reimport request sends `service` (`<namespace>/<Kind>/<name>/<container>`), `version` and the full tag list, and the report labels are rewritten to the stable workload before upload. DefectDojo closes, on reimport, only the findings whose service equals the service of the request, or the findings without a service when the request has none; the Trivy Operator parser always gives a service, so without it in the request no fixed finding is ever closed. DefectDojo also writes an empty version when `version` is missing, and replaces the test tags with the tags of the request.

## Considered Options

- Rely on the parser's service (the first version). Rejected: the close set is then empty, and the operator closed only findings of other services.
- Close missing findings in the operator. Rejected: it duplicates what reimport already does with the right service.

## Consequences

- The service is part of the finding hash. Changing its format reopens every finding as new, so the format is fixed.
- The `description` holds the resource kind and name from the report labels. Without the label rewrite, each rollout gives new findings.
- The service is at most 200 characters and the title at most 255. A longer value is shortened in a fixed way (start of the value, `~`, a hash of the full value), so the same workload always gives the same value.
- Tags are sent with `apply_tags_to_findings`, so findings can be filtered by tag without a join through the test.
