package trivy

import (
	"context"

	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// workloadReport returns the name of the workload report that names the same test as a report of one of its
// ReplicaSets or Jobs and that can be uploaded, or "" when there is none or the report is a workload report itself.
// The report on a ReplicaSet or Job is not uploaded then, whichever of the two the listing delivers first.
// A report that is marked for deletion, expired, broken or of a held rejected version does not count. The candidates
// come from the listing of the pass; a candidate whose record is gone or no longer under the key is skipped.
func (r *Reconciler) workloadReport(
	ctx context.Context,
	p *pass,
	key testKey,
	rec reportMeta,
	workload trivy.Workload,
) (string, error) {
	if namesWorkload(rec.obj, workload) {
		return "", nil
	}

	under := containerKey{kind: workload.Kind, name: workload.Name, container: trivy.ContainerOf(rec.obj)}

	for _, name := range p.reports.candidates(rec.kind, under) {
		cand, ok := p.reports.record(rec.kind, name)
		if !ok || !isUnder(cand, under) {
			continue
		}

		uploadable, err := r.uploadable(ctx, p, key, under, cand)
		if err != nil {
			return "", err
		}

		if uploadable {
			return name, nil
		}
	}

	return "", nil
}

func isUnder(rec reportMeta, under containerKey) bool {
	key, ok := indexKey(rec.obj)

	return ok && key == under
}

// uploadable reports whether the candidate is a report reimportOne uploads for the test: its version is not a held
// rejected version and the report is not broken. A candidate reimported in an earlier pass is known to be neither;
// the facts of any other are read once, without keeping the body. A read that returns another version replaces the
// record, and the candidate is judged again on it; a candidate gone at the read does not count.
func (r *Reconciler) uploadable(
	ctx context.Context,
	p *pass,
	key testKey,
	under containerKey,
	cand reportMeta,
) (bool, error) {
	if known, uploadable := r.knownUploadable(p, key, cand); known {
		return uploadable, nil
	}

	f, read, body, err := p.bodies.facts(ctx, cand)
	if err != nil {
		return false, err
	}

	if read == sameVersion {
		return f.broken == "", nil
	}

	cand, ok := p.reports.adopt(cand.kind, cand.obj.GetName(), read, body)
	if !ok || !isUnder(cand, under) {
		return false, nil
	}

	if known, uploadable := r.knownUploadable(p, key, cand); known {
		return uploadable, nil
	}

	f, _, _, err = p.bodies.facts(ctx, cand)
	if err != nil {
		return false, err
	}

	return f.broken == "", nil
}

// knownUploadable answers uploadable from memory: a held rejected version is not uploadable, the version the test was
// last reimported from is. known is false when memory does not tell.
func (r *Reconciler) knownUploadable(p *pass, key testKey, cand reportMeta) (known, uploadable bool) {
	version := versionOf(cand.obj)

	if r.isRejected(p.target.Namespace, key, version) {
		return true, false
	}

	if last := r.lastReimport(p.target.Namespace, key); last != nil && last.reportVersion == version {
		return true, true
	}

	return false, false
}
