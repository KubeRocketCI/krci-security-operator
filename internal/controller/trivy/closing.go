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

// sweepInterval is the period of the check for tests of namespaces that are gone or excluded.
const sweepInterval = 6 * time.Hour

// namespaceProduct returns the namespace product of the cluster, found by its exact name. found is false while
// no import has created it. DefectDojo matches the name without regard to case, so the name is compared here.
func (r *Reconciler) namespaceProduct(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
) (product defectdojo.Product, found bool, err error) {
	name := trivy.ProductName(r.config.ClusterName, namespace)

	products, err := dd.ListProductsByName(ctx, r.config.ProductType, name)
	if err != nil {
		return defectdojo.Product{}, false,
			fmt.Errorf("failed to list DefectDojo products of namespace %s: %w", namespace, err)
	}

	for _, p := range products {
		if p.Name == name {
			return p, true, nil
		}
	}

	return defectdojo.Product{}, false, nil
}

// productTypeMissing reports whether err says that DefectDojo does not list the configured Product Type: it does
// not exist yet, or the token cannot read it. It logs that at Info once per process.
func (r *Reconciler) productTypeMissing(ctx context.Context, err error) bool {
	if !errors.Is(err, defectdojo.ErrProductTypeNotFound) {
		return false
	}

	r.productTypeLogged.Do(func() {
		ctrl.LoggerFrom(ctx).Info("Could not find the Product Type in DefectDojo", "productType", r.config.ProductType)
	})

	return true
}

// productTests returns the tests of the Trivy engagement of the namespace product.
func (r *Reconciler) productTests(
	ctx context.Context,
	dd DefectDojo,
	product defectdojo.Product,
) ([]defectdojo.Test, error) {
	tests, err := dd.ListTests(ctx, product, trivy.EngagementTrivyOperator)
	if err != nil {
		return nil, fmt.Errorf("failed to list DefectDojo tests of product %s: %w", product.Name, err)
	}

	return tests, nil
}

// closeStaleTests closes the owned tests of the namespace product whose title is not the title of a container of a
// live stable workload: the workload is gone or the container is no longer in its pod template.
// A missing report and a workload scaled to zero close nothing.
func (r *Reconciler) closeStaleTests(
	ctx context.Context,
	dd DefectDojo,
	target trivy.Target,
	product defectdojo.Product,
) error {
	tests, err := r.productTests(ctx, dd, product)
	if err != nil {
		return err
	}

	var expected map[string]struct{}

	listed := make(map[int]struct{}, len(tests))

	for _, test := range tests {
		listed[test.ID] = struct{}{}

		if !r.ownsTest(ctx, test) {
			continue
		}

		if expected == nil {
			if expected, err = r.expectedTitles(ctx, target.Namespace); err != nil {
				return err
			}
		}

		if _, ok := expected[test.Title]; ok {
			continue
		}

		if err = r.closeTest(ctx, dd, target.Namespace, test, "no container of a workload has its title"); err != nil {
			return err
		}
	}

	r.pruneTests(target.Namespace, listed)

	return nil
}

// expectedTitles returns the titles of the tests of the namespace that its live workloads call for: one per report
// kind, stable workload and container of its pod template. The workloads are listed at the time of the call, not
// taken from the lists of the import: a workload created in between keeps its test.
func (r *Reconciler) expectedTitles(ctx context.Context, namespace string) (map[string]struct{}, error) {
	resolver := trivy.NewWorkloadResolver(r.reader, namespace)

	workloads, err := resolver.StableWorkloads(ctx)
	if err != nil {
		return nil, err
	}

	titles := map[string]struct{}{}

	for _, workload := range workloads {
		containers, _, err := resolver.Containers(ctx, workload)
		if err != nil {
			return nil, fmt.Errorf("failed to read the containers of %s: %w", workload, err)
		}

		for container := range containers {
			for _, kind := range r.config.ReportKinds {
				titles[trivy.TestTitle(kind, workload, container)] = struct{}{}
			}
		}
	}

	return titles, nil
}

// release closes every owned test of a namespace that is gone or excluded, once per process
// until the namespace is imported again, and makes sure its product has its tags. The product and the tests stay.
func (r *Reconciler) release(ctx context.Context, dd DefectDojo, namespace string) error {
	product, found, err := r.namespaceProduct(ctx, dd, namespace)
	if r.productTypeMissing(ctx, err) {
		// The lookup cannot tell whether the namespace has tests: the next pass or sweep looks again.
		return nil
	}

	if err != nil {
		return err
	}

	if !found {
		if !r.isReleased(namespace) {
			r.markReleased(namespace)
		}

		return nil
	}

	if !r.isReleased(namespace) {
		if err = r.closeOwnedTests(ctx, dd, namespace, product); err != nil {
			return err
		}

		r.markReleased(namespace)
	}

	return r.setProductTags(ctx, dd, namespace, product)
}

// closeOwnedTests closes every owned test of the namespace product.
func (r *Reconciler) closeOwnedTests(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
	product defectdojo.Product,
) error {
	tests, err := r.productTests(ctx, dd, product)
	if err != nil {
		return err
	}

	for _, test := range tests {
		if !r.ownsTest(ctx, test) {
			continue
		}

		if err = r.closeTest(ctx, dd, namespace, test, "the namespace is gone or excluded"); err != nil {
			return err
		}
	}

	return nil
}

// closeTest closes a test that is not closed yet; the callers check that the operator owns it.
func (r *Reconciler) closeTest(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
	test defectdojo.Test,
	reason string,
) error {
	if r.isClosed(namespace, test.ID) {
		return nil
	}

	if err := dd.CloseTest(ctx, test); err != nil {
		return fmt.Errorf("failed to close DefectDojo test %d: %w", test.ID, err)
	}

	r.markClosed(namespace, test.ID)

	ctrl.LoggerFrom(ctx).Info("Closed a test", "test", test.ID, "title", test.Title, "reason", reason)

	return nil
}

// ownsTest reports whether the operator of this cluster owns the test; every other test stays untouched.
func (r *Reconciler) ownsTest(ctx context.Context, test defectdojo.Test) bool {
	if trivy.IsOwned(test, r.config.ClusterName) {
		return true
	}

	ctrl.LoggerFrom(ctx).V(1).Info("Skipped a test of another owner", "test", test.ID, "title", test.Title,
		"product", test.Product, "scanType", test.ScanType)

	return false
}

// setProductTags makes sure the namespace product has its two product tags and keeps its other tags. The product
// comes from a lookup of the same pass. PATCH replaces the tags of a product, so the full list is sent.
func (r *Reconciler) setProductTags(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
	product defectdojo.Product,
) error {
	tags, changed := trivy.WithProductTags(product.Tags, r.config.ClusterName, namespace)
	if !changed {
		return nil
	}

	if err := dd.SetProductTags(ctx, product.ID, tags); err != nil {
		return fmt.Errorf("failed to set the tags of DefectDojo product %s: %w", product.Name, err)
	}

	ctrl.LoggerFrom(ctx).Info("Set the tags of a product", "product", product.Name)

	return nil
}

// runSweeper looks for namespaces whose tests need closing at start and then periodically,
// which also covers a namespace deleted or excluded while the operator was down.
func (r *Reconciler) runSweeper(ctx context.Context) error {
	ctx = ctrl.LoggerInto(ctx, ctrl.Log.WithName(controllerName).WithName("sweeper"))

	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		if err := r.sweep(ctx); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Failed to sweep the namespace products of the cluster")
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// sweep hands the namespaces that need the controller to it, and writes nothing to DefectDojo: the closing of a
// namespace and the repair of its product tags are serialized with its imports by the workqueue.
// A namespace needs it when it has a product although it no longer exists or is excluded and was not released yet,
// or when its product has wrong or missing product tags.
// A failure for one namespace does not stop the others; the errors are joined.
func (r *Reconciler) sweep(ctx context.Context) error {
	dd, available, err := r.defectDojo(ctx)
	if err != nil {
		return err
	}

	if !available {
		return nil
	}

	products, err := dd.ListProducts(ctx, r.config.ProductType, trivy.ProductPrefix(r.config.ClusterName))
	if r.productTypeMissing(ctx, err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to list DefectDojo products: %w", err)
	}

	candidates, withProduct := r.sweepCandidates(products)

	var errs []error

	for _, candidate := range candidates {
		importable, nsErr := r.isImportable(ctx, candidate.namespace)
		if nsErr != nil {
			errs = append(errs, nsErr)

			continue
		}

		if importable && !candidate.tagsWrong {
			continue
		}

		if !importable && !candidate.tagsWrong && r.isReleased(candidate.namespace) {
			continue
		}

		if wakeErr := r.wakeNamespace(ctx, candidate.namespace); wakeErr != nil {
			return errors.Join(append(errs, wakeErr)...)
		}
	}

	r.pruneReleased(withProduct)

	return errors.Join(errs...)
}

// sweepCandidate is a namespace that has a namespace product of the cluster.
type sweepCandidate struct {
	namespace string
	// tagsWrong is true when the product lacks a product tag or holds one with a wrong value.
	tagsWrong bool
}

// sweepCandidates returns, in the order of the products and once each, the namespaces of the namespace products
// of the cluster, as a list and as a set. The name filter of the list is a "contains" match, so a product whose
// name does not start with the cluster prefix is dropped here.
func (r *Reconciler) sweepCandidates(products []defectdojo.Product) ([]sweepCandidate, map[string]struct{}) {
	var candidates []sweepCandidate

	withProduct := map[string]struct{}{}

	for _, product := range products {
		namespace, ok := trivy.NamespaceOfProduct(r.config.ClusterName, product.Name)
		if !ok {
			continue
		}

		if _, seen := withProduct[namespace]; seen {
			continue
		}

		withProduct[namespace] = struct{}{}

		_, tagsWrong := trivy.WithProductTags(product.Tags, r.config.ClusterName, namespace)
		candidates = append(candidates, sweepCandidate{namespace: namespace, tagsWrong: tagsWrong})
	}

	return candidates, withProduct
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
