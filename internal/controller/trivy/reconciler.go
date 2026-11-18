package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
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
	GetTest(ctx context.Context, testID int) (defectdojo.Test, error)
	ListTests(ctx context.Context, tag string) ([]defectdojo.Test, error)
	CloseTest(ctx context.Context, testID int) error
	CloseFindingsOutsideService(ctx context.Context, testID int, service string) (int, error)
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
	// healed holds, per namespace, the live tests whose findings of stale services were closed.
	healed map[string]map[int]struct{}
	// rejectedVersions holds, per namespace, the report versions DefectDojo rejected; they are not uploaded again.
	rejectedVersions map[string]map[importKey]reportVersion
	// released holds the namespaces whose owned tests were closed because the namespace is gone or excluded.
	released map[string]struct{}

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
		healed:   map[string]map[int]struct{}{},

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
	// keepOpenTitles holds the titles of tests that stay open although no import of this pass reached them:
	// those whose workload only has superseded reports so far, and those whose report DefectDojo rejected.
	keepOpenTitles map[string]struct{}
	// rejected holds the versions of the reports of this pass that DefectDojo rejected, in this pass or before.
	rejected map[importKey]reportVersion
	// unlisted holds the configured report kinds the pass could not list completely.
	unlisted []string
	// unattributed holds the report kinds with a skipped report that names no resource: no test is known for it.
	unattributed map[string]struct{}
}

// keepOpenKind keeps the tests of a report kind open in this pass.
func (p *pass) keepOpenKind(kind string) {
	if p.unattributed == nil {
		p.unattributed = map[string]struct{}{}
	}

	p.unattributed[kind] = struct{}{}
}

// reject records a report version DefectDojo rejected: its test stays open and keeps reflecting the earlier import.
func (p *pass) reject(key importKey, version reportVersion, title string, prev importedReport, hasPrev bool) {
	p.rejected[key] = version
	p.keepOpenTitles[title] = struct{}{}

	if hasPrev {
		p.current[key] = prev
	}
}

// listed reports whether the pass listed every report of the kind of the test title.
func (p *pass) listed(title string) bool {
	return !slices.Contains(p.unlisted, trivy.TitleKind(title))
}

// keepsOpen reports whether a test that no import of the pass reached stays open: its workload only has superseded
// reports so far, DefectDojo rejected its report, or the pass could not list its report kind.
func (p *pass) keepsOpen(title string) bool {
	if _, ok := p.keepOpenTitles[title]; ok {
		return true
	}

	if _, ok := p.unattributed[trivy.TitleKind(title)]; ok {
		return true
	}

	return !p.listed(title)
}

// forget drops what the pass found for the reports of a kind, before a restarted listing delivers them again.
// A report deleted in between then no longer counts as live.
func (p *pass) forget(kind string) {
	ofKind := func(title string) bool { return trivy.TitleKind(title) == kind }

	maps.DeleteFunc(p.current, func(key importKey, _ importedReport) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.rejected, func(key importKey, _ reportVersion) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.keepOpenTitles, func(title string, _ struct{}) bool { return ofKind(title) })
	delete(p.unattributed, kind)
}

// syncNamespace imports the reports of an imported namespace page by page and closes the tests of workloads
// that are gone. Tests are closed only after every report was imported: a failed import hides which tests
// are still alive. The tests of a report kind the pass could not list stay as they are.
func (r *Reconciler) syncNamespace(ctx context.Context, dd DefectDojo, target trivy.Target) error {
	p := &pass{
		target:         target,
		resolver:       trivy.NewWorkloadResolver(r.reader, target.Namespace),
		components:     map[trivy.Workload]string{},
		current:        map[importKey]importedReport{},
		keepOpenTitles: map[string]struct{}{},
		rejected:       map[importKey]reportVersion{},
	}

	if err := r.importReports(ctx, dd, p); err != nil {
		return err
	}

	if len(p.unlisted) > 0 {
		ctrl.LoggerFrom(ctx).Info("Report kinds are not served by the cluster, their tests stay as they are",
			"kinds", p.unlisted)
	}

	if len(p.unlisted) == len(r.config.ReportKinds) {
		return nil
	}

	r.keepImports(target.Namespace, p)

	return r.closeStaleTests(ctx, dd, target, p)
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

// importOne resolves and imports one report.
func (r *Reconciler) importOne(ctx context.Context, dd DefectDojo, p *pass, report *unstructured.Unstructured) error {
	log := ctrl.LoggerFrom(ctx)

	if report.GetDeletionTimestamp() != nil {
		return nil
	}

	if reason := trivy.BrokenReport(report); reason != "" {
		return r.skipBroken(ctx, p, report, reason)
	}

	workload, state, err := p.resolver.ResolveReport(ctx, report)
	if err != nil {
		return err
	}

	if state == trivy.WorkloadGone {
		return nil
	}

	component, err := r.component(ctx, p.components, p.target.Namespace, workload)
	if err != nil {
		return err
	}

	imp := trivy.ReportImport(p.target, report, workload, component)

	if state == trivy.WorkloadSuperseded {
		p.keepOpenTitles[imp.TestTitle] = struct{}{}

		return nil
	}

	key := importKey{product: imp.Product, engagement: imp.Engagement, title: imp.TestTitle}

	version := reportVersion{uid: report.GetUID(), resourceVersion: report.GetResourceVersion()}
	prev, hasPrev := r.lastImport(p.target.Namespace, key)

	if hasPrev && prev.uid == version.uid && prev.resourceVersion == version.resourceVersion {
		p.current[key] = prev

		return nil
	}

	if r.isRejected(p.target.Namespace, key, version) {
		p.reject(key, version, imp.TestTitle, prev, hasPrev)

		log.V(1).Info("Report version was rejected before, not uploaded again",
			"report", report.GetName(), "kind", report.GetKind())

		return nil
	}

	entry, err := r.importReport(ctx, dd, p.target.Namespace, imp, report, workload)
	if err != nil {
		if !defectdojo.IsRejectedReport(err) {
			return err
		}

		log.Error(err, "DefectDojo rejected a report version, it is not uploaded again until it changes",
			"report", report.GetName(), "kind", report.GetKind())
		rejectedReports.WithLabelValues(report.GetKind()).Inc()

		r.recordRejection(p.target.Namespace, key, version)
		p.reject(key, version, imp.TestTitle, prev, hasPrev)

		return nil
	}

	p.current[key] = entry

	r.recordImport(p.target.Namespace, key, entry)

	log.Info("Imported a report", "report", report.GetName(), "kind", report.GetKind(),
		"product", imp.Product, "engagement", imp.Engagement, "test", entry.testID)

	return nil
}

// skipBroken logs a report that is not uploaded (see trivy.BrokenReport) and keeps its test open.
// It is not recorded as imported. A report that names no resource names no test: every test of its report kind
// stays open.
func (r *Reconciler) skipBroken(ctx context.Context, p *pass, report *unstructured.Unstructured, reason string) error {
	ctrl.LoggerFrom(ctx).Info("Skipped a broken report",
		"report", report.GetName(), "kind", report.GetKind(), "reason", reason)

	if !trivy.NamesResource(report) {
		p.keepOpenKind(report.GetKind())

		return nil
	}

	workload, state, err := p.resolver.ResolveReport(ctx, report)
	if err != nil {
		return err
	}

	if state != trivy.WorkloadGone {
		p.keepOpenTitles[trivy.ReportTitle(report, workload)] = struct{}{}
	}

	return nil
}

func (r *Reconciler) importReport(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
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

	r.closeStaleServices(ctx, dd, namespace, res.TestID, trivy.Service(report, workload))

	return importedReport{uid: report.GetUID(), resourceVersion: report.GetResourceVersion(), testID: res.TestID}, nil
}

// component returns the component tag value of a workload: it reads the labels and annotations of the top
// workload object and falls back to the namespace name when the workload has none or is gone.
func (r *Reconciler) component(
	ctx context.Context,
	known map[trivy.Workload]string,
	namespace string,
	workload trivy.Workload,
) (string, error) {
	if c, ok := known[workload]; ok {
		return c, nil
	}

	component := trivy.TagSafe(namespace)

	if gvk, ok := workload.GVK(); ok {
		obj := &metav1.PartialObjectMetadata{}
		obj.SetGroupVersionKind(gvk)

		err := r.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: workload.Name}, obj)

		switch {
		case err == nil:
			component = trivy.Component(obj.GetLabels(), obj.GetAnnotations(), namespace, r.config.ComponentPrefixes)
		case !k8sErrors.IsNotFound(err):
			return "", fmt.Errorf("failed to get %s %s: %w", gvk.Kind, workload.Name, err)
		}
	}

	known[workload] = component

	return component, nil
}

// closeStaleServices closes, once per test and process, the findings written under another service:
// reports imported before their labels named the stable workload left one set of findings per ReplicaSet.
// Only a test of this operator is touched.
// A failure is retried after the next import.
func (r *Reconciler) closeStaleServices(
	ctx context.Context,
	dd DefectDojo,
	namespace string,
	testID int,
	service string,
) {
	if r.isHealed(namespace, testID) {
		return
	}

	test, err := dd.GetTest(ctx, testID)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Could not read the test of stale services", "test", testID)

		return
	}

	if !r.ownsTest(ctx, test) {
		return
	}

	closed, err := dd.CloseFindingsOutsideService(ctx, testID, service)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Could not close findings of a stale service", "test", testID)

		return
	}

	r.markHealed(namespace, testID)

	if closed > 0 {
		ctrl.LoggerFrom(ctx).Info("Closed findings of a stale service", "test", testID, "findings", closed)
	}
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

// keepImports forgets the tests that no report reflects any more, and the rejected versions of reports that are
// gone. What is remembered about a kind the pass could not list stays, and its tests count as live in the pass.
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

func (r *Reconciler) markOpen(namespace string, testID int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.closed[namespace], testID)
}

func (r *Reconciler) isHealed(namespace string, testID int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.healed[namespace][testID]

	return ok
}

func (r *Reconciler) markHealed(namespace string, testID int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.healed, namespace, testID, struct{}{})
}

// pruneTests keeps the closed IDs that DefectDojo still lists for the namespace and the healed IDs of live tests.
func (r *Reconciler) pruneTests(namespace string, listed, live map[int]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	keepIDs(r.closed, namespace, listed)
	keepIDs(r.healed, namespace, live)
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
	delete(r.healed, namespace)
}

// markImportable clears the released mark of a namespace that the pass imports.
func (r *Reconciler) markImportable(namespace string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.released, namespace)
}

// pruneReleased forgets the released namespaces that own no test any more.
func (r *Reconciler) pruneReleased(withTests map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for namespace := range r.released {
		if _, ok := withTests[namespace]; !ok {
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
