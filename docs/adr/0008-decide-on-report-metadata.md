# A pass decides on report metadata and reads the body of a new report version only

A pass lists the metadata of the reports of a namespace and reads the full body of a report only for a report version it has not read before, or for an upload. The body of a report version tells the pass two things, its image and whether it is broken, and they do not change while the version holds; the operator keeps them in memory per report version. An unchanged namespace is then passed without one report body read, unless a reimport is due, such as the retry of a rejected report version. The body is the largest part of a report (a VulnerabilityReport is 40 KB at the median with the severity filter of `edp-cluster-add-ons` and up to 3 MB without it; its metadata is about 2 KB), and the full LIST of every pass read about 47 MB per `resyncPeriod` on a cluster of 1,000 Pods.

The metadata of a report kind watched at start is listed from the informer cache, which holds it for the watch; the metadata of a kind the cluster did not serve at start is listed through the API reader, so a report CRD installed later is imported on the next resync. The listing is sorted by report name before the reports are decided, because the choice of the report of a test depends on the order and the cache has none.

## Considered Options

- List the full reports on every pass (the earlier version). Rejected: the bytes read grow with the report size of every namespace on every pass, also when nothing changed.
- Keep the image on the record of the reimported report of a test. Rejected: it covers only the version a test reflects; a broken report, a report that loses the choice of its test and a rejected version are read again on every pass.
- Read the report version back from the upload marker. Rejected: the marker is only compared, never parsed (ADR 0006), and it holds nothing for a broken report.
- Watch the full reports. Rejected: a report can reach 3 MB, so the cache would hold every report of the cluster.
- List the metadata through the API reader only. Rejected: the informer cache holds the same metadata already, and a watched kind would be listed twice.

## Consequences

- The body of an unknown report version is read before the choice of its test, so a broken report takes no choice, as with the full LIST.
- A read that returns another report version than the listing (a changed report, or one created again under the same name) replaces the listed metadata with the read one, for the report and for its entry among the reports on stable workloads, and the report is decided again from its first check, once. A report gone at the read is not current. A report on a stable workload that no longer qualifies after such a read keeps no other report of its container out.
- The body read for an upload must be the report version the marker was built from. Another version, or a report gone at that read, is not uploaded in the pass: its test stays as it is, like a test of a held rejected version, and the change is imported by the pass its event wakes, or the next resync for a kind that is not watched.
- After a restart or a leader change the first pass reads the body of each current report version with a GET. Historical reports are skipped before their body is read. A report read early to decide another report of its container is read again for its own upload. There is no fallback to the full LIST.
- A pass holds at most two report bodies at a time: the report it decides and one read to decide it.
- The informer cache can hold a report that was just deleted, longer when its watch is interrupted. The pass may then choose it for its test and upload nothing for the test until the cache catches up. Closing reads no report (ADR 0004), so a stale entry never closes a test.
- What the pass keeps per report version is bounded by the listing: at the end of every pass, also one that failed, the facts of a kind whose listing completed keep only the current version of each listed report, the read one where a read replaced the listed one. The facts of a kind whose listing did not complete stay; a released namespace drops all of them.
- `REPORT_KINDS` is deduplicated, so a kind is listed once per pass.
