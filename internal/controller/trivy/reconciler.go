package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	// reportsPageSize is the number of full reports held in memory at a time.
	reportsPageSize = 10
	// maxListRestarts is how often the listing of a report kind starts again after its continue token expired.
	maxListRestarts = 3
	// dependencyRetry is the longest wait before a namespace is retried while an optional dependency is absent.
	dependencyRetry = 5 * time.Minute
	// secretTTL is how long the credentials are used before the Secret is read again.
	secretTTL = time.Minute
	// resyncJitter is the share of resyncPeriod by which the periodic requeue is spread.
	resyncJitter = 0.1
	// wakeBuffer is the capacity of the queue of namespaces the sweeper hands to the controller.
	wakeBuffer = 1024
)

// DefectDojo is the part of the DefectDojo client the controller uses.
type DefectDojo interface {
	Reimport(ctx context.Context, r defectdojo.ReimportRequest) (defectdojo.ReimportResult, error)
	// ListProducts returns the products of the product type whose name contains name, or
	// defectdojo.ErrProductTypeNotFound.
	ListProducts(ctx context.Context, productType, name string) ([]defectdojo.Product, error)
	// ListProductsByName returns the products of the product type whose name equals name, ignoring case, or
	// defectdojo.ErrProductTypeNotFound.
	ListProductsByName(ctx context.Context, productType, name string) ([]defectdojo.Product, error)
	// ListTests returns the Trivy Operator Scan tests of the engagement of the product.
	ListTests(ctx context.Context, product defectdojo.Product, engagement string) ([]defectdojo.Test, error)
	// CloseTest mitigates the active findings of the test and keeps the test.
	CloseTest(ctx context.Context, test defectdojo.Test) error
	// SetProductTags replaces the tags of the product.
	SetProductTags(ctx context.Context, productID int, tags []string) error
}

// Connector returns a DefectDojo client for the given credentials.
type Connector func(url, token string) DefectDojo

// NewConnector binds the shared DefectDojo client state to the credentials of each call.
func NewConnector(c *defectdojo.Client) Connector {
	return func(url, token string) DefectDojo { return c.WithCredentials(url, token) }
}

// rejectedReports counts the report versions DefectDojo rejected with a client error.
var rejectedReports = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "krci_security_operator_rejected_reports_total",
	Help: "Trivy Operator report versions that DefectDojo rejected, by report kind.",
}, []string{"kind"})

func init() { metrics.Registry.MustRegister(rejectedReports) }

// reportVersion identifies one version of a report.
type reportVersion struct {
	uid             types.UID
	resourceVersion string
}

// importKey identifies a DefectDojo test inside a namespace.
type importKey struct {
	product    string
	engagement string
	title      string
}

// importedReport is the report version a DefectDojo test currently reflects.
type importedReport struct {
	uid             types.UID
	resourceVersion string
	testID          int
}

type credentials struct{ url, token string }

// Reconciler imports the Trivy Operator reports of one namespace per request into DefectDojo.
//
// The credentials Secret and the Trivy Operator CRDs are optional: while one is missing the namespace is
// requeued without an error. Every other failure is returned, so the workqueue backs off and counts it.
// All closing of the tests of a namespace happens in Reconcile, which the workqueue serializes per namespace;
// the sweeper only wakes namespaces up.
// The reconciler adds no finalizer and writes nothing to the cluster.
type Reconciler struct {
	// cache serves the watched Namespaces.
	cache client.Reader
	// reader reads without a cache: reports, workloads and the credentials Secret.
	reader  client.Reader
	config  Config
	connect Connector
	now     func() time.Time
	// random returns a number in [0, 1).
	random func() float64
	// wake carries the namespaces the sweeper hands to the controller.
	wake chan event.GenericEvent

	mu sync.Mutex
	// imported holds, per namespace, the report each test was last imported from.
	// It is lost on restart; the next pass re-imports every report and converges.
	imported map[string]map[importKey]importedReport
	// closed holds, per namespace, the tests closed by the operator that DefectDojo still lists.
	closed map[string]map[int]struct{}
	// rejectedVersions holds, per namespace, the report versions DefectDojo rejected; they are not uploaded again.
	rejectedVersions map[string]map[importKey]reportVersion
	// released holds the namespaces whose owned tests were closed because the namespace is gone or excluded.
	released map[string]struct{}

	// productTypeLogged guards the one Info log of a Product Type that DefectDojo does not list.
	productTypeLogged sync.Once

	credMu       sync.Mutex
	creds        credentials
	credsAt      time.Time
	credsValid   bool
	secretLogged bool
}

// NewReconciler returns a Reconciler. cache serves Namespaces, reader serves everything else.
func NewReconciler(cache, reader client.Reader, cfg Config, connect Connector) *Reconciler {
	return &Reconciler{
		cache:    cache,
		reader:   reader,
		config:   cfg,
		connect:  connect,
		now:      time.Now,
		random:   rand.Float64,
		wake:     make(chan event.GenericEvent, wakeBuffer),
		imported: map[string]map[importKey]importedReport{},
		closed:   map[string]map[int]struct{}{},

		rejectedVersions: map[string]map[importKey]reportVersion{},
		released:         map[string]struct{}{},
	}
}

// Reconcile imports the reports of the namespace named by the request, or closes its tests when the namespace
// is gone, terminating or excluded.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	namespace := request.Name
	ctx = ctrl.LoggerInto(ctx, ctrl.LoggerFrom(ctx).WithValues("namespace", namespace))

	dd, available, err := r.defectDojo(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}

	if !available {
		return reconcile.Result{RequeueAfter: r.dependencyRetry()}, nil
	}

	ns, err := r.liveNamespace(ctx, namespace)
	if err != nil {
		return reconcile.Result{}, err
	}

	if ns == nil {
		return reconcile.Result{}, r.release(ctx, dd, namespace)
	}

	if r.excluded(ns.Name) {
		if err = r.release(ctx, dd, namespace); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: r.resyncAfter()}, nil
	}

	r.markImportable(namespace)

	if err = r.syncNamespace(ctx, dd, r.target(namespace)); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{RequeueAfter: r.resyncAfter()}, nil
}

func (r *Reconciler) dependencyRetry() time.Duration {
	return min(r.config.ResyncPeriod, dependencyRetry)
}

// resyncAfter is the resync period spread by up to resyncJitter either way, so namespaces do not requeue in lockstep.
func (r *Reconciler) resyncAfter() time.Duration {
	factor := 1 + (2*r.random()-1)*resyncJitter

	return time.Duration(float64(r.config.ResyncPeriod) * factor)
}

// defectDojo returns a client for the credentials of the Secret.
// The Secret is read at most once per secretTTL. available is false, without an error, while the Secret is absent
// or holds no url or token; a failed read is an error.
func (r *Reconciler) defectDojo(ctx context.Context) (dd DefectDojo, available bool, err error) {
	if c, ok := r.cachedCredentials(); ok {
		return r.connect(c.url, c.token), true, nil
	}

	secret := &corev1.Secret{}

	key := client.ObjectKey{Namespace: r.config.OperatorNamespace, Name: r.config.SecretName}
	if err = r.reader.Get(ctx, key, secret); err != nil {
		if k8sErrors.IsNotFound(err) {
			r.logSecret(ctx, "DefectDojo credentials Secret is absent, reports are not imported", key.Name)

			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to get the DefectDojo credentials Secret %s: %w", key.Name, err)
	}

	c := credentials{url: string(secret.Data[SecretKeyURL]), token: string(secret.Data[SecretKeyToken])}
	if c.url == "" || c.token == "" {
		r.logSecret(ctx, "DefectDojo credentials Secret has no url or token, reports are not imported", key.Name)

		return nil, false, nil
	}

	r.storeCredentials(c)

	return r.connect(c.url, c.token), true, nil
}

func (r *Reconciler) cachedCredentials() (credentials, bool) {
	r.credMu.Lock()
	defer r.credMu.Unlock()

	if r.credsValid && r.now().Sub(r.credsAt) < secretTTL {
		return r.creds, true
	}

	return credentials{}, false
}

func (r *Reconciler) storeCredentials(c credentials) {
	r.credMu.Lock()
	defer r.credMu.Unlock()

	r.creds, r.credsAt, r.credsValid = c, r.now(), true
}

// logSecret logs a missing or invalid Secret at Info the first time in the process and at V(1) after that.
func (r *Reconciler) logSecret(ctx context.Context, msg, secret string) {
	r.credMu.Lock()
	first := !r.secretLogged
	r.secretLogged = true
	r.credMu.Unlock()

	log := ctrl.LoggerFrom(ctx)
	if !first {
		log = log.V(1)
	}

	log.Info(msg, "secret", secret)
}

// pass holds what one pass over a namespace accumulates across pages of reports.
type pass struct {
	target   trivy.Target
	resolver *trivy.WorkloadResolver
	// components caches the component tag per workload.
	components map[trivy.Workload]string
	// current holds the tests the pass imported or found up to date.
	current map[importKey]importedReport
	// claimed holds, per test, the report the pass takes it from.
	claimed map[importKey]claim
	// rejected holds the versions of the reports of this pass that DefectDojo rejected, in this pass or before.
	rejected map[importKey]reportVersion
	// unlisted holds the configured report kinds the pass could not list completely.
	unlisted []string
	// uploadErrors holds the uploads that failed in this pass; the reports are tried again in the next pass.
	uploadErrors []error
	// ownReports holds, per report kind, the metadata of its reports by resource and container. It is listed at the
	// first report that needs it.
	ownReports map[string]map[ownKey][]ownCandidate
	// ignored holds the reports whose ignoring the pass logged.
	ignored map[ignoredReport]struct{}
}

// ignoredReport identifies a report that lost the choice of its test.
type ignoredReport struct {
	title  string
	report string
}

// claim ranks the current reports of one test: the report on the stable workload itself comes first (the CronJob
// before its Jobs), then the lowest report name.
type claim struct {
	report string
	// own is true when the report names the stable workload, not a ReplicaSet or Job of it.
	own bool
}

func (c claim) before(other claim) bool {
	if c.own != other.own {
		return c.own
	}

	return c.report < other.report
}

// reject records a report version DefectDojo rejected: its test keeps reflecting the earlier import.
func (p *pass) reject(key importKey, version reportVersion, prev importedReport, hasPrev bool) {
	p.rejected[key] = version

	if hasPrev {
		p.current[key] = prev
	}
}

// listed reports whether the pass listed every report of the kind of the test title.
func (p *pass) listed(title string) bool {
	return !slices.Contains(p.unlisted, trivy.TitleKind(title))
}

// forget drops what the pass found for the reports of a kind, before a restarted listing delivers them again.
// A report deleted in between then no longer counts as current.
func (p *pass) forget(kind string) {
	ofKind := func(title string) bool { return trivy.TitleKind(title) == kind }

	maps.DeleteFunc(p.current, func(key importKey, _ importedReport) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.claimed, func(key importKey, _ claim) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.rejected, func(key importKey, _ reportVersion) bool { return ofKind(key.title) })
}

// syncNamespace imports the reports of an imported namespace page by page, closes the tests of workloads and
// containers that are gone and makes sure the namespace product has its tags.
// A report that is missing closes nothing. A failed upload keeps its report for the next pass and does not stop
// the other uploads and the closing; its error is returned with the others.
func (r *Reconciler) syncNamespace(ctx context.Context, dd DefectDojo, target trivy.Target) error {
	p := &pass{
		target:     target,
		resolver:   trivy.NewWorkloadResolver(r.reader, target.Namespace),
		components: map[trivy.Workload]string{},
		current:    map[importKey]importedReport{},
		claimed:    map[importKey]claim{},
		rejected:   map[importKey]reportVersion{},
		ownReports: map[string]map[ownKey][]ownCandidate{},
		ignored:    map[ignoredReport]struct{}{},
	}

	if err := r.importReports(ctx, dd, p); err != nil {
		return err
	}

	// The close builds its own lists, see expectedTitles.
	p.resolver, p.ownReports = nil, nil

	if len(p.unlisted) > 0 {
		ctrl.LoggerFrom(ctx).Info("Report kinds are not served by the cluster, their reports are not imported",
			"kinds", p.unlisted)
	}

	r.keepImports(target.Namespace, p)

	product, found, err := r.namespaceProduct(ctx, dd, target.Namespace)
	if err != nil && !r.productTypeMissing(ctx, err) {
		return errors.Join(append(p.uploadErrors, err)...)
	}

	if !found {
		r.pruneTests(target.Namespace, nil)

		return errors.Join(p.uploadErrors...)
	}

	closeErr := r.closeStaleTests(ctx, dd, target, product)

	return errors.Join(append(p.uploadErrors, closeErr, r.setProductTags(ctx, dd, target.Namespace, product))...)
}

// importPage resolves and imports the reports of one page.
// A report version DefectDojo rejects is remembered, not uploaded again, and does not fail the pass.
func (r *Reconciler) importPage(ctx context.Context, dd DefectDojo, p *pass, page []unstructured.Unstructured) error {
	for i := range page {
		err := r.importOne(ctx, dd, p, &page[i])

		// The report is not needed after its pass: free it before the rest of the page is imported.
		page[i].Object = nil

		if err != nil {
			return err
		}
	}

	return nil
}

// importOne resolves and imports one report. A report is not imported when it is broken, marked for deletion,
// of a workload that is gone, superseded or of a kind the operator does not read, of a container that is not in the
// pod template of its workload, or when another current report of the same test comes first.
func (r *Reconciler) importOne(ctx context.Context, dd DefectDojo, p *pass, report *unstructured.Unstructured) error {
	log := ctrl.LoggerFrom(ctx).WithValues("report", report.GetName(), "kind", report.GetKind())

	if report.GetDeletionTimestamp() != nil {
		return nil
	}

	if reason := trivy.BrokenReport(report); reason != "" {
		log.Info("Skipped a broken report", "reason", reason)

		return nil
	}

	if trivy.ExpiredReport(report) {
		log.V(1).Info("Skipped a report that Trivy Operator deletes at once")

		return nil
	}

	workload, ok, err := r.currentWorkload(ctx, p, report)
	if err != nil || !ok {
		return err
	}

	component, err := r.component(ctx, p.components, p.target.Namespace, workload)
	if err != nil {
		return err
	}

	imp := trivy.ReportImport(p.target, report, workload, component)
	key := importKey{product: imp.Product, engagement: imp.Engagement, title: imp.TestTitle}
	mine := claim{report: report.GetName(), own: namesWorkload(report, workload)}

	version := reportVersion{uid: report.GetUID(), resourceVersion: report.GetResourceVersion()}
	prev, hasPrev := r.lastImport(p.target.Namespace, key)
	rejected := r.isRejected(p.target.Namespace, key, version)

	// A rejected report on the workload itself is not a current report: it does not hold the test against the others.
	if rejected && mine.own {
		p.reject(key, version, prev, hasPrev)

		log.V(1).Info("Report version was rejected before, not uploaded again")

		return nil
	}

	if !p.claim(ctx, key, mine) {
		return nil
	}

	if hasPrev && prev.uid == version.uid && prev.resourceVersion == version.resourceVersion {
		p.current[key] = prev

		return nil
	}

	if rejected {
		p.reject(key, version, prev, hasPrev)

		log.V(1).Info("Report version was rejected before, not uploaded again")

		return nil
	}

	used, err := r.ownReport(ctx, p, key, report, workload)
	if err != nil {
		return err
	}

	if used != "" {
		p.logIgnored(ctx, key.title, used, report.GetName())

		return nil
	}

	entry, err := r.importReport(ctx, dd, imp, report, workload)
	if err != nil {
		return r.uploadFailed(ctx, p, report, key, version, prev, hasPrev, err)
	}

	p.current[key] = entry

	r.recordImport(p.target.Namespace, key, entry)

	log.Info("Imported a report", "product", imp.Product, "engagement", imp.Engagement, "test", entry.testID)

	return nil
}

// currentWorkload returns the stable workload of a report that describes it as it is now. ok is false, without an
// error, when the report is not imported for that reason.
func (r *Reconciler) currentWorkload(
	ctx context.Context,
	p *pass,
	report *unstructured.Unstructured,
) (workload trivy.Workload, ok bool, err error) {
	log := ctrl.LoggerFrom(ctx).WithValues("report", report.GetName(), "kind", report.GetKind())

	workload, state, err := p.resolver.ResolveReport(ctx, report)
	if err != nil {
		return trivy.Workload{}, false, err
	}

	switch state {
	case trivy.WorkloadGone:
		log.V(1).Info("Skipped a report of a workload that is gone", "workload", workload.String())

		return workload, false, nil
	case trivy.WorkloadSuperseded:
		log.V(1).Info("Skipped a report of a superseded revision", "workload", workload.String())

		return workload, false, nil
	case trivy.WorkloadUnsupported:
		log.V(1).Info("Skipped a report of a resource kind the operator does not read", "workload", workload.String())

		return workload, false, nil
	case trivy.WorkloadCurrent:
		// The container is checked below.
	}

	containers, _, err := p.resolver.Containers(ctx, workload)
	if err != nil {
		return trivy.Workload{}, false, fmt.Errorf("failed to read the containers of %s: %w", workload, err)
	}

	container := report.GetLabels()[trivy.LabelContainerName]
	if _, in := containers[container]; !in {
		log.V(1).Info("Skipped a report of a container that is not in the pod template",
			"workload", workload.String(), "container", container)

		return workload, false, nil
	}

	return workload, true, nil
}

// namesWorkload reports whether the report is on the stable workload itself, not on a ReplicaSet or Job of it.
func namesWorkload(report *unstructured.Unstructured, workload trivy.Workload) bool {
	return strings.EqualFold(report.GetLabels()[trivy.LabelResourceKind], workload.Kind)
}

// claim records the report as the one its test is imported from, unless another current report of the same test
// comes first. The report that loses is logged.
func (p *pass) claim(ctx context.Context, key importKey, mine claim) bool {
	held, taken := p.claimed[key]
	if !taken || mine.before(held) {
		if taken {
			p.logIgnored(ctx, key.title, mine.report, held.report)
		}

		p.claimed[key] = mine

		return true
	}

	p.logIgnored(ctx, key.title, held.report, mine.report)

	return false
}

// logIgnored logs a report of a test that another current report takes the place of, once per report and pass.
func (p *pass) logIgnored(ctx context.Context, title, used, ignored string) {
	if _, done := p.ignored[ignoredReport{title: title, report: ignored}]; done {
		return
	}

	p.ignored[ignoredReport{title: title, report: ignored}] = struct{}{}

	ctrl.LoggerFrom(ctx).Info("Ignored a report of a test that has another current report",
		"test", title, "used", used, "ignored", ignored)
}

// uploadFailed handles a failed upload. A rejection by DefectDojo is permanent for the report version: it is
// remembered and not uploaded again. Any other failure leaves the result in DefectDojo unknown: the operator closes
// nothing for the report, keeps the error for the end of the pass and uploads the report again in the next pass.
func (r *Reconciler) uploadFailed(
	ctx context.Context,
	p *pass,
	report *unstructured.Unstructured,
	key importKey,
	version reportVersion,
	prev importedReport,
	hasPrev bool,
	err error,
) error {
	if !defectdojo.IsRejectedReport(err) {
		if ctx.Err() != nil {
			return err
		}

		p.uploadErrors = append(p.uploadErrors, err)

		return nil
	}

	ctrl.LoggerFrom(ctx).Error(err, "DefectDojo rejected a report version, it is not uploaded again until it changes",
		"report", report.GetName(), "kind", report.GetKind())
	rejectedReports.WithLabelValues(report.GetKind()).Inc()

	r.recordRejection(p.target.Namespace, key, version)
	p.reject(key, version, prev, hasPrev)

	return nil
}

func (r *Reconciler) importReport(
	ctx context.Context,
	dd DefectDojo,
	imp trivy.Import,
	report *unstructured.Unstructured,
	workload trivy.Workload,
) (importedReport, error) {
	payload, err := json.Marshal(trivy.Payload(report, workload))
	if err != nil {
		return importedReport{}, fmt.Errorf("failed to marshal report %s: %w", report.GetName(), err)
	}

	res, err := dd.Reimport(ctx, imp.Request(r.config.ProductType, r.now(), payload))
	if err != nil {
		return importedReport{}, fmt.Errorf("failed to import report %s: %w", report.GetName(), err)
	}

	if res.TestID == 0 {
		return importedReport{}, fmt.Errorf("defectdojo did not return a test for report %s", report.GetName())
	}

	return importedReport{uid: report.GetUID(), resourceVersion: report.GetResourceVersion(), testID: res.TestID}, nil
}

// component returns the app tag value of a workload: it reads the labels and annotations of the top
// workload object. It is "" when no source names a component or the workload object is gone.
func (r *Reconciler) component(
	ctx context.Context,
	known map[trivy.Workload]string,
	namespace string,
	workload trivy.Workload,
) (string, error) {
	if c, ok := known[workload]; ok {
		return c, nil
	}

	component := ""

	if gvk, ok := workload.GVK(); ok {
		obj := &metav1.PartialObjectMetadata{}
		obj.SetGroupVersionKind(gvk)

		err := r.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: workload.Name}, obj)

		switch {
		case err == nil:
			component = trivy.Component(obj.GetLabels(), obj.GetAnnotations(), r.config.ComponentPrefixes)
		case !k8sErrors.IsNotFound(err):
			return "", fmt.Errorf("failed to get %s %s: %w", gvk.Kind, workload.Name, err)
		}
	}

	known[workload] = component

	return component, nil
}

// importReports imports every page of reports of the configured kinds in the namespace; only one page is held at
// a time. The kinds it could not list completely are recorded in the pass.
func (r *Reconciler) importReports(ctx context.Context, dd DefectDojo, p *pass) error {
	for _, kind := range r.config.ReportKinds {
		listed, err := r.importKind(ctx, dd, p, kind)
		if err != nil {
			return err
		}

		if !listed {
			p.unlisted = append(p.unlisted, kind)
		}
	}

	return nil
}

// importKind imports every page of the reports of one kind in the namespace. The result is false when the cluster
// does not serve the kind, also when it stops serving it while its pages are listed. An expired continue token
// starts the listing again, up to maxListRestarts times: the pass forgets what the earlier listing found, and the
// reports imported or rejected before are skipped as unchanged.
func (r *Reconciler) importKind(ctx context.Context, dd DefectDojo, p *pass, kind string) (bool, error) {
	gvk := trivy.ReportGVK(kind)
	base := []client.ListOption{client.InNamespace(p.target.Namespace), client.Limit(reportsPageSize)}
	opts := base
	restarts := 0

	for {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk.GroupVersion().WithKind(kind + "List"))

		err := r.reader.List(ctx, list, opts...)

		switch {
		case err == nil:
			// The page is imported below.
		case meta.IsNoMatchError(err) || k8sErrors.IsNotFound(err):
			return false, nil
		case continueExpired(err) && restarts < maxListRestarts:
			restarts++
			opts = base

			p.forget(kind)

			continue
		case continueExpired(err):
			return false, fmt.Errorf("failed to list %s after %d restarts: %w", kind, restarts, err)
		default:
			return false, fmt.Errorf("failed to list %s: %w", kind, err)
		}

		for i := range list.Items {
			// The item kind is not always set on a list read.
			list.Items[i].SetGroupVersionKind(gvk)
		}

		if err := r.importPage(ctx, dd, p, list.Items); err != nil {
			return false, err
		}

		if list.GetContinue() == "" {
			return true, nil
		}

		opts = append(slices.Clone(base), client.Continue(list.GetContinue()))
	}
}

// continueExpired reports whether a list failed because its continue token is too old (HTTP 410).
func continueExpired(err error) bool {
	return k8sErrors.IsResourceExpired(err) || k8sErrors.IsGone(err)
}

func (r *Reconciler) lastImport(namespace string, key importKey) (importedReport, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.imported[namespace][key]

	return entry, ok
}

func (r *Reconciler) recordImport(namespace string, key importKey, entry importedReport) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.imported, namespace, key, entry)
	delete(r.closed[namespace], entry.testID)
}

// recordRejection remembers a rejected report version at once, so a pass that fails later does not upload it again.
func (r *Reconciler) recordRejection(namespace string, key importKey, version reportVersion) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.rejectedVersions, namespace, key, version)
}

// keepImports forgets the tests that no current report reflects any more, and the rejected versions of reports that
// are not current. What is remembered about a kind the pass could not list stays.
func (r *Reconciler) keepImports(namespace string, p *pass) {
	r.mu.Lock()
	defer r.mu.Unlock()

	store(r.imported, namespace, withUnlisted(p, r.imported[namespace], p.current))
	store(r.rejectedVersions, namespace, withUnlisted(p, r.rejectedVersions[namespace], p.rejected))
}

// store sets the entries of the namespace, and forgets the namespace when it has none.
func store[V any](m map[string]map[importKey]V, namespace string, entries map[importKey]V) {
	if len(entries) == 0 {
		delete(m, namespace)

		return
	}

	m[namespace] = entries
}

// withUnlisted adds to found the remembered entries of the report kinds the pass could not list, and returns found.
func withUnlisted[V any](p *pass, remembered, found map[importKey]V) map[importKey]V {
	for key, v := range remembered {
		if !p.listed(key.title) {
			found[key] = v
		}
	}

	return found
}

func (r *Reconciler) isRejected(namespace string, key importKey, version reportVersion) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	v, ok := r.rejectedVersions[namespace][key]

	return ok && v == version
}

func (r *Reconciler) isClosed(namespace string, testID int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.closed[namespace][testID]

	return ok
}

func (r *Reconciler) markClosed(namespace string, testID int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.closed, namespace, testID, struct{}{})
}

// pruneTests keeps the closed IDs that DefectDojo still lists for the namespace.
func (r *Reconciler) pruneTests(namespace string, listed map[int]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	keepIDs(r.closed, namespace, listed)
}

func (r *Reconciler) isReleased(namespace string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.released[namespace]

	return ok
}

// markReleased records that the owned tests of the namespace were closed and drops everything else known about it.
func (r *Reconciler) markReleased(namespace string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.released[namespace] = struct{}{}

	delete(r.imported, namespace)
	delete(r.rejectedVersions, namespace)
	delete(r.closed, namespace)
}

// markImportable clears the released mark of a namespace that the pass imports.
func (r *Reconciler) markImportable(namespace string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.released, namespace)
}

// pruneReleased forgets the released namespaces that have no product any more.
func (r *Reconciler) pruneReleased(withProduct map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for namespace := range r.released {
		if _, ok := withProduct[namespace]; !ok {
			delete(r.released, namespace)
		}
	}
}

// put sets m[namespace][key], creating the map of the namespace when needed.
func put[K comparable, V any](m map[string]map[K]V, namespace string, key K, value V) {
	if m[namespace] == nil {
		m[namespace] = map[K]V{}
	}

	m[namespace][key] = value
}

func keepIDs(m map[string]map[int]struct{}, namespace string, keep map[int]struct{}) {
	for id := range m[namespace] {
		if _, ok := keep[id]; !ok {
			delete(m[namespace], id)
		}
	}

	if len(m[namespace]) == 0 {
		delete(m, namespace)
	}
}
