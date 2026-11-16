package trivy

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

// sweepInterval is the period of the check for tests of namespaces that are gone or out of scope.
const sweepInterval = 6 * time.Hour

// closeStaleTests closes the owned tests of the namespace that no longer reflect a running workload container.
// That covers removed workloads and tests written under another scope before the namespace changed its scope.
// A test whose Deployment has only superseded reports so far (a rollout is in progress), and a test whose
// report was rejected, stay open.
func (r *Reconciler) closeStaleTests(ctx context.Context, dd DefectDojo, target trivy.Target, p *pass) error {
	live := make(map[int]struct{}, len(p.current))
	for _, entry := range p.current {
		live[entry.testID] = struct{}{}
	}

	tests, err := dd.ListTests(ctx, trivy.NamespaceTag(target.Namespace))
	if err != nil {
		return fmt.Errorf("failed to list DefectDojo tests of namespace %s: %w", target.Namespace, err)
	}

	listed := make(map[int]struct{}, len(tests))

	for _, test := range tests {
		listed[test.ID] = struct{}{}

		if !trivy.IsOwned(test, r.config.ClusterName) || !test.HasTag(trivy.NamespaceTag(target.Namespace)) {
			continue
		}

		if _, ok := live[test.ID]; ok {
			r.markOpen(target.Namespace, test.ID)

			continue
		}

		if _, ok := p.keepOpenTitles[test.Title]; ok {
			continue
		}

		if err = r.closeTest(ctx, dd, target.Namespace, test); err != nil {
			return err
		}
	}

	r.pruneTests(target.Namespace, listed, live)

	return nil
}

// release closes every owned test of a namespace that is gone or out of scope, once per process
// until the namespace is in scope again.
func (r *Reconciler) release(ctx context.Context, dd DefectDojo, namespace string) error {
	if r.isReleased(namespace) {
		return nil
	}

	tests, err := dd.ListTests(ctx, trivy.NamespaceTag(namespace))
	if err != nil {
		return fmt.Errorf("failed to list DefectDojo tests of namespace %s: %w", namespace, err)
	}

	for _, test := range tests {
		if !test.HasTag(trivy.NamespaceTag(namespace)) || !r.ownsTest(ctx, test) {
			continue
		}

		if err = r.closeTest(ctx, dd, namespace, test); err != nil {
			return err
		}
	}

	r.markReleased(namespace)

	return nil
}

// closeTest closes a test that is not closed yet; the callers check that the operator owns it.
func (r *Reconciler) closeTest(ctx context.Context, dd DefectDojo, namespace string, test defectdojo.Test) error {
	if r.isClosed(namespace, test.ID) {
		return nil
	}

	if err := dd.CloseTest(ctx, test.ID); err != nil {
		return fmt.Errorf("failed to close DefectDojo test %d: %w", test.ID, err)
	}

	r.markClosed(namespace, test.ID)

	ctrl.LoggerFrom(ctx).Info("Closed a test", "test", test.ID, "title", test.Title)

	return nil
}

// ownsTest reports whether the operator of this cluster wrote the test; every other test stays untouched.
func (r *Reconciler) ownsTest(ctx context.Context, test defectdojo.Test) bool {
	if trivy.IsOwned(test, r.config.ClusterName) {
		return true
	}

	ctrl.LoggerFrom(ctx).V(1).Info("Test is not owned by this operator, skipping", "test", test.ID, "title", test.Title)

	return false
}

// runSweeper looks for namespaces whose tests need closing at start and then periodically,
// which also covers a namespace deleted or a scope switched off while the operator was down.
func (r *Reconciler) runSweeper(ctx context.Context) error {
	ctx = ctrl.LoggerInto(ctx, ctrl.Log.WithName(controllerName).WithName("sweeper"))

	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		if err := r.sweep(ctx); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Sweep failed, will retry")
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// sweep finds the namespaces that own open tests although the namespace no longer exists or is out of scope,
// and hands them to the controller, which closes the tests. The sweeper closes nothing itself, so the
// closing of a namespace is serialized with its imports by the workqueue.
// A failure for one namespace does not stop the others; the errors are joined.
func (r *Reconciler) sweep(ctx context.Context) error {
	dd, available, err := r.defectDojo(ctx)
	if err != nil {
		return err
	}

	if !available {
		return nil
	}

	tests, err := dd.ListTests(ctx, trivy.ClusterTag(r.config.ClusterName))
	if err != nil {
		return fmt.Errorf("failed to list DefectDojo tests: %w", err)
	}

	candidates, withTest := r.sweepCandidates(tests)

	var errs []error

	for _, namespace := range candidates {
		if r.isReleased(namespace) {
			continue
		}

		inScope, scopeErr := r.namespaceInScope(ctx, namespace)
		if scopeErr != nil {
			errs = append(errs, scopeErr)

			continue
		}

		if inScope {
			continue
		}

		if wakeErr := r.wakeNamespace(ctx, namespace); wakeErr != nil {
			return errors.Join(append(errs, wakeErr)...)
		}
	}

	r.pruneReleased(withTest)

	return errors.Join(errs...)
}

// sweepCandidates returns, in the order of the tests and once each, the namespaces that still have an owned test,
// as a list and as a set.
func (r *Reconciler) sweepCandidates(tests []defectdojo.Test) (candidates []string, withTest map[string]struct{}) {
	withTest = map[string]struct{}{}

	for _, test := range tests {
		namespace, ok := test.TagValue(trivy.TagPrefixNamespace)
		if !ok || !trivy.IsOwned(test, r.config.ClusterName) {
			continue
		}

		if _, seen := withTest[namespace]; !seen {
			candidates = append(candidates, namespace)
		}

		withTest[namespace] = struct{}{}
	}

	return candidates, withTest
}

// wakeNamespace asks the controller to reconcile the namespace.
func (r *Reconciler) wakeNamespace(ctx context.Context, namespace string) error {
	obj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}

	select {
	case r.wake <- event.GenericEvent{Object: obj}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to wake namespace %s: %w", namespace, ctx.Err())
	}
}
