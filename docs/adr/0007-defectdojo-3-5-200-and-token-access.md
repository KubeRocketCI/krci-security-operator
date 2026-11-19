# DefectDojo 3.5.200 or later, and the token access is the installer's choice

The operator supports DefectDojo 3.5.200 or later. The fake DefectDojo, the docs and the testbed check follow 3.5.200. Earlier versions may work but are not tested, and no rule of the operator handles them. The operator uses the access of the token it is given and does not create or change DefectDojo users or access. The person who installs the operator chooses the token user from the options in `docs/trivy.md` (DefectDojo API token): an authorized user of a Product Type created in advance (recommended), a staff user, or a superuser (testbeds only).

## Considered Options

- Support 2.55 or later, as the first spec did. Rejected: the reimport serialization, the Trivy Operator parser, the hash fields and the access model differ across these versions, and each difference needs its own rule, test and testbed run. 3.5.200 is the version the platform installs and tests.
- Document the access per major version (2.x roles, 3.x authorized users). Rejected with 2.55 support.
- Detect the 403 after the operator created a Product Type that its token cannot use, and log one clear error. Rejected: the case is a setup error that the docs name; the operator closes no test and loses no finding while it lasts, and the retry ends when the access is corrected.
- Make the operator add its user to the authorized users of the Product Type it created. Rejected: it needs member management, which DefectDojo gives only to staff users, so the least-privilege token cannot do it.

## Consequences

- DefectDojo 3.5.200 grants access by the superuser and staff flags and by the authorized users of a Product Type or product; role assignments are not read. An authorized user of the Product Type can read, import, edit and add in all of its products, and nothing outside it.
- A user that is not staff and creates the Product Type on first use is not made an authorized user of it. Every later request gets 403 and the namespace is retried without end. The docs list this case as not supported.
- The operator deletes nothing in DefectDojo, so no option needs the delete permission.
- A newer DefectDojo version that changes the reimport, the parser, the hash fields or the access model needs the fake DefectDojo, the docs and this ADR updated, and a testbed run.
