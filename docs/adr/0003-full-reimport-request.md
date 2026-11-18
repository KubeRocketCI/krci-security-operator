# Every reimport sends the service, the version and all tags

Each reimport request sends `service` (`<namespace>/<Kind>/<name>/<container>`), `version` and the full tag list, and the report labels are rewritten to the stable workload before upload. DefectDojo closes, on reimport, only the findings whose service equals the service of the request, or the findings without a service when the request has none; the Trivy Operator parser always gives a service, so without it in the request no fixed finding is ever closed. DefectDojo also writes an empty version when `version` is missing, and replaces the test tags with the tags of the request.

## Considered Options

- Rely on the parser's service (the first version). Rejected: the close set is then empty, and the operator closed only findings of other services.
- Close missing findings in the operator. Rejected: it duplicates what reimport already does with the right service.

## Consequences

- The finding hash is the title, the severity, the vulnerability ids and the description of the finding (the DefectDojo setting for Trivy Operator Scan), and the service, which DefectDojo adds to every hash. Changing the service format reopens every finding as new, so the format is fixed.
- The title holds the installed version of the package, and the `description` the container and the resource kind, name and namespace from the report labels. Without the label rewrite, each rollout gives new findings.
- The workload name is the `trivy-operator.resource.name` label, else the annotation of the same name: Trivy Operator writes a long name (not a valid label value) only to the annotation. The label rewrite always writes the full name, so the parser sees it.
- The service is at most 200 characters, the title at most 255 and the version at most 100. A longer value is shortened in a fixed way (start of the value, `~`, a hash of the full value), so the same workload always gives the same value.
- Tags are set on the test only, not on findings. DefectDojo adds request tags to findings and never removes them, so finding tags would keep old images and apps. Findings are filtered by test tag (`test__tags`).
