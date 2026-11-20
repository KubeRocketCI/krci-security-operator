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

// remoteTests is the namespace product and its tests as DefectDojo lists them. A pass reads them once, when it first
// needs them. found is false while no import has created the product.
type remoteTests struct {
	read       bool
	product    defectdojo.Product
	found      bool
	productErr error
	tests      []defectdojo.Test
	testsErr   error
	// latest holds, per title, the Trivy Operator Scan test with the highest ID in the last engagement: the one a
	// reimport writes into.
	latest map[string]defectdojo.Test
}

// readRemote reads the namespace product and its tests unless the pass did.
func (r *Reconciler) readRemote(ctx context.Context, dd DefectDojo, p *pass) *remoteTests {
	remote := &p.remote
	if remote.read {
		return remote
	}

	*remote = remoteTests{read: true}

	remote.product, remote.found, remote.productErr = r.namespaceProduct(ctx, dd, p.target.Namespace)
	if remote.productErr != nil || !remote.found {
		return remote
	}

	remote.tests, remote.testsErr = r.productTests(ctx, dd, remote.product)

	remote.latest = make(map[string]defectdojo.Test, len(remote.tests))
	for _, test := range remote.tests {
		if !test.LastEngagement || test.ScanType != defectdojo.ScanTypeTrivyOperator {
			continue
		}

		if have, ok := remote.latest[test.Title]; !ok || test.ID > have.ID {
			remote.latest[test.Title] = test
		}
	}

	return remote
}

// remoteAfterUploads returns what DefectDojo lists once the uploads of the pass are done. The read before the
// uploads is repeated when the pass sent a reimport, and when it did not find the product, which an upload may have
// created; the failure of a read before the uploads fails the pass, so it is not kept here.
func (r *Reconciler) remoteAfterUploads(ctx context.Context, dd DefectDojo, p *pass) *remoteTests {
	if remote := &p.remote; remote.read && (p.uploaded || !remote.found) {
		remote.read = false
	}

	return r.readRemote(ctx, dd, p)
}

// locateTest returns the test that a reimport of the upload writes into; exists is false when it creates one.
// The test of a report reimported in this process is known by its ID and marker. Otherwise the tests of the
// namespace product are read once per pass; a failed read, other than a Product Type that DefectDojo does not list,
// is returned: the pass does not upload while it is unknown what DefectDojo holds.
func (r *Reconciler) locateTest(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	u reportUpload,
) (test defectdojo.Test, exists bool, err error) {
	if u.prev != nil {
		return defectdojo.Test{ID: u.prev.testID, BuildID: u.prev.marker}, true, nil
	}

	remote := r.readRemote(ctx, dd, p)

	if remote.productErr != nil && !errors.Is(remote.productErr, defectdojo.ErrProductTypeNotFound) {
		return defectdojo.Test{}, false, remote.productErr
	}

	if remote.testsErr != nil {
		return defectdojo.Test{}, false, remote.testsErr
	}

	test, exists = remote.latest[u.key.title]

	return test, exists, nil
}

// closeStaleTests closes the owned tests of the namespace product whose title is not the title of a container of a
// live stable workload: the workload is gone or the container is no longer in its pod template.
// A missing report and a workload scaled to zero close nothing.
func (r *Reconciler) closeStaleTests(
	ctx context.Context,
	dd DefectDojo,
	target trivy.Target,
	tests []defectdojo.Test,
) error {
	var (
		expected map[string]struct{}
		err      error
	)

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
	resolver := trivy.NewWorkloadResolver(r.reader, namespace, r.config.ComponentPrefixes)

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

	return r.setProductTags(ctx, dd, namespace, product, r.wantedLabelTags(nil, product.Tags))
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

	res, err := dd.CloseTest(ctx, test)
	if err != nil {
		return fmt.Errorf("failed to close DefectDojo test %d: %w", test.ID, err)
	}

	r.markClosed(namespace, test.ID)

	if !res.FoundActive() {
		ctrl.LoggerFrom(ctx).V(1).Info("Skipped a test without active findings",
			"test", test.ID, "title", test.Title, "reason", reason)

		return nil
	}

	kv := []any{
		"test", test.ID, "title", test.Title, "reason", reason,
		"reimports", res.Reimports, "closedOneByOne", res.OneByOne,
	}

	// The failure names the status and the body of an answer of DefectDojo.
	if res.Fallback != nil {
		kv = append(kv, "fallback", res.Fallback.Error())
	}

	ctrl.LoggerFrom(ctx).Info("Closed a test", kv...)

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

// setProductTags makes sure the namespace product has its two product tags and exactly the namespace label tags
// labelTags, and keeps its other tags. The product comes from a lookup of the same pass. PATCH replaces the tags of a
// product, so the full list is sent.
func (r *Reconciler) setProductTags(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
	product defectdojo.Product,
	labelTags []string,
) error {
	tags, changed := trivy.WithProductTags(product.Tags, r.config.ClusterName, namespace, labelTags)
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
		if err := r.sweep(ctx); err != nil && ctx.Err() == nil {
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
// or when its product has wrong or missing product tags, the namespace label tags included.
// An ended context stops the sweep before it prunes the released namespaces.
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

	if err = r.wakeCandidates(ctx, candidates); err != nil && ctx.Err() != nil {
		return err
	}

	r.pruneReleased(withProduct)

	return err
}

// wakeCandidates wakes each candidate namespace that needs the controller. A failure to read one namespace does not
// stop the others; the errors are joined. An ended context stops it at the next failed read or wake.
func (r *Reconciler) wakeCandidates(ctx context.Context, candidates []sweepCandidate) error {
	var errs []error

	for _, candidate := range candidates {
		wake, err := r.needsController(ctx, candidate)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}

			errs = append(errs, err)

			continue
		}

		if !wake {
			continue
		}

		if err = r.wakeNamespace(ctx, candidate.namespace); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}

	return errors.Join(errs...)
}

// needsController reports whether the controller has to reconcile the namespace of the candidate: the tags of its
// product differ from what setProductTags sets, or the namespace is not imported and its tests are not closed yet.
func (r *Reconciler) needsController(ctx context.Context, c sweepCandidate) (bool, error) {
	ns, err := r.importableNamespace(ctx, c.namespace)
	if err != nil {
		return false, err
	}

	_, tagsWrong := trivy.WithProductTags(c.tags, r.config.ClusterName, c.namespace, r.wantedLabelTags(ns, c.tags))

	return tagsWrong || (ns == nil && !r.isReleased(c.namespace)), nil
}

// sweepCandidate is a namespace that has a namespace product of the cluster.
type sweepCandidate struct {
	namespace string
	tags      []string
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

		candidates = append(candidates, sweepCandidate{namespace: namespace, tags: product.Tags})
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
