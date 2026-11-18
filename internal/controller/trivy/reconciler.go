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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	// reportsPageSize is the number of full reports held in memory at a time.
	reportsPageSize = 10
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
	// CloseTest mitigates the findings of the test, by empty reimports and one by one, and keeps the test.
	CloseTest(ctx context.Context, test defectdojo.Test) (defectdojo.CloseResult, error)
	// SetBuildID sets the build_id of the test.
	SetBuildID(ctx context.Context, testID int, buildID string) error
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

// versionOf returns the version of a report.
func versionOf(report metav1.Object) reportVersion {
	return reportVersion{uid: report.GetUID(), resourceVersion: report.GetResourceVersion()}
}

// testKey identifies a DefectDojo test inside a namespace.
type testKey struct {
	product    string
	engagement string
	title      string
}

// reimportedReport is the report version a DefectDojo test currently reflects.
type reimportedReport struct {
	reportVersion
	// marker is the upload marker of the request that went with the report version.
	marker string
	testID int
}

// rejection is a report version that DefectDojo rejected and the time of the last upload of it.
type rejection struct {
	version reportVersion
	at      time.Time
}

type credentials struct{ url, token string }

// Reconciler reimports the Trivy Operator reports of one namespace per request into DefectDojo.
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
	// reimported holds, per namespace, the report each test was last reimported from.
	// It is lost on restart; the next pass takes the report versions from the build_id of the tests.
	reimported map[string]map[testKey]reimportedReport
	// closed holds, per namespace, the tests closed by the operator that DefectDojo still lists.
	closed map[string]map[int]struct{}
	// rejectedVersions holds, per namespace, the report versions DefectDojo rejected; each is uploaded again once
	// per resyncPeriod.
	rejectedVersions map[string]map[testKey]rejection
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
		cache:      cache,
		reader:     reader,
		config:     cfg,
		connect:    connect,
		now:        time.Now,
		random:     rand.Float64,
		wake:       make(chan event.GenericEvent, wakeBuffer),
		reimported: map[string]map[testKey]reimportedReport{},
		closed:     map[string]map[int]struct{}{},

		rejectedVersions: map[string]map[testKey]rejection{},
		released:         map[string]struct{}{},
	}
}

// Reconcile reimports the reports of the namespace named by the request, or closes its tests when the namespace
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
			r.logSecret(ctx, "Could not find the DefectDojo credentials Secret", key.Name)

			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to get the DefectDojo credentials Secret %s: %w", key.Name, err)
	}

	c := credentials{url: string(secret.Data[SecretKeyURL]), token: string(secret.Data[SecretKeyToken])}
	if c.url == "" || c.token == "" {
		r.logSecret(ctx, "Found no url or token in the DefectDojo credentials Secret", key.Name)

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
	// current holds the tests the pass reimported or found up to date.
	current map[testKey]reimportedReport
	// chosen holds, per test, the chosen report.
	chosen map[testKey]choice
	// rejected holds the versions of the reports of this pass that DefectDojo rejected, in this pass or before.
	rejected map[testKey]rejection
	// unlisted holds the configured report kinds the pass could not list completely.
	unlisted []string
	// uploadErrors holds the uploads that failed in this pass; the reports are tried again in the next pass.
	uploadErrors []error
	// reportIndex holds, per report kind, the metadata of its reports by resource and container. It is listed at the
	// first report that needs it.
	reportIndex map[string]map[containerKey][]indexedReport
	// ignored holds the reports whose ignoring the pass logged.
	ignored map[ignoredReport]struct{}
	// remote holds what DefectDojo lists for the namespace product, once it was needed.
	remote remoteTests
	// uploaded is true once the pass sent a reimport: the tests list read before it is out of date.
	uploaded bool
}

// ignoredReport identifies a report that lost the choice of its test.
type ignoredReport struct {
	title  string
	report string
}

// choice ranks the current reports of one test: the workload report comes first (the CronJob before its Jobs), then
// the lowest report name.
type choice struct {
	report string
	// onWorkload is true when the report names the stable workload, not a ReplicaSet or Job of it.
	onWorkload bool
}

func (c choice) before(other choice) bool {
	if c.onWorkload != other.onWorkload {
		return c.onWorkload
	}

	return c.report < other.report
}

// reportUpload is a report that is about to be uploaded, with what is known about its test.
type reportUpload struct {
	report  *unstructured.Unstructured
	key     testKey
	version reportVersion
	// marker is the upload marker of the report with the request of its test.
	marker string
	// prev is the report the test reflects; nil when none is known.
	prev *reimportedReport
	// rejection is the remembered rejection of this version; nil when there is none.
	rejection *rejection
}

// reject records a report version DefectDojo rejected: its test keeps reflecting the earlier reimport.
func (p *pass) reject(u reportUpload, rec rejection) {
	p.rejected[u.key] = rec

	if u.prev != nil {
		p.current[u.key] = *u.prev
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

	maps.DeleteFunc(p.current, func(key testKey, _ reimportedReport) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.chosen, func(key testKey, _ choice) bool { return ofKind(key.title) })
	maps.DeleteFunc(p.rejected, func(key testKey, _ rejection) bool { return ofKind(key.title) })
}

// syncNamespace reimports the reports of a namespace page by page, closes the tests of workloads and
// containers that are gone and makes sure the namespace product has its tags.
// A report that is missing closes nothing. A failed upload keeps its report for the next pass and does not stop
// the other uploads and the closing; its error is returned with the others.
func (r *Reconciler) syncNamespace(ctx context.Context, dd DefectDojo, target trivy.Target) error {
	p := &pass{
		target:      target,
		resolver:    trivy.NewWorkloadResolver(r.reader, target.Namespace),
		components:  map[trivy.Workload]string{},
		current:     map[testKey]reimportedReport{},
		chosen:      map[testKey]choice{},
		rejected:    map[testKey]rejection{},
		reportIndex: map[string]map[containerKey][]indexedReport{},
		ignored:     map[ignoredReport]struct{}{},
	}

	if err := r.reimportReports(ctx, dd, p); err != nil {
		return err
	}

	// The close builds its own lists, see expectedTitles.
	p.resolver, p.reportIndex = nil, nil

	if len(p.unlisted) > 0 {
		ctrl.LoggerFrom(ctx).Info("Skipped the report kinds that the cluster does not serve", "kinds", p.unlisted)
	}

	r.keepReimported(target.Namespace, p)

	remote := r.remoteAfterUploads(ctx, dd, p)

	if remote.productErr != nil && !r.productTypeMissing(ctx, remote.productErr) {
		return errors.Join(append(p.uploadErrors, remote.productErr)...)
	}

	if !remote.found {
		r.pruneTests(target.Namespace, nil)

		return errors.Join(p.uploadErrors...)
	}

	closeErr := remote.testsErr
	if closeErr == nil {
		closeErr = r.closeStaleTests(ctx, dd, target, remote.tests)
	}

	return errors.Join(append(p.uploadErrors, closeErr, r.setProductTags(ctx, dd, target.Namespace, remote.product))...)
}

// reimportPage reimports the reports of one page.
// A report version DefectDojo rejects is remembered, see Reconciler.rejectedVersions, and does not fail the pass.
func (r *Reconciler) reimportPage(ctx context.Context, dd DefectDojo, p *pass, page []unstructured.Unstructured) error {
	for i := range page {
		err := r.reimportOne(ctx, dd, p, &page[i])

		// The report is not needed after its pass: free it before the rest of the page is reimported.
		page[i].Object = nil

		if err != nil {
			return err
		}
	}

	return nil
}

// reimportOne reimports one report. A report is not reimported when it is broken, marked for deletion,
// of a workload that is gone, superseded or of a kind the operator does not read, of a container that is not in the
// pod template of its workload, or when another current report of the same test comes first.
func (r *Reconciler) reimportOne(ctx context.Context, dd DefectDojo, p *pass, report *unstructured.Unstructured) error {
	log := ctrl.LoggerFrom(ctx).WithValues("report", report.GetName(), "kind", report.GetKind())

	if skipReport(log, report) {
		return nil
	}

	workload, image, ok, err := r.currentWorkload(ctx, p, report)
	if err != nil || !ok {
		return err
	}

	component, err := r.component(ctx, p.components, p.target.Namespace, workload)
	if err != nil {
		return err
	}

	dest := trivy.NewReimport(p.target, report, workload, component, image)
	key := testKey{product: dest.Product, engagement: dest.Engagement, title: dest.TestTitle}
	mine := choice{report: report.GetName(), onWorkload: namesWorkload(report, workload)}

	u := reportUpload{report: report, key: key, version: versionOf(report), marker: dest.UploadMarker(report)}
	u.prev = r.lastReimport(p.target.Namespace, key)
	u.rejection = r.rejectionOf(p.target.Namespace, key, u.version)
	held := u.rejection != nil && !r.retryDue(*u.rejection)

	// A workload report of a held rejected version is not a current report: it takes no choice of the test.
	if held && mine.onWorkload {
		p.keepRejected(log, u)

		return nil
	}

	if !p.choose(ctx, key, mine) {
		return nil
	}

	if u.prev != nil && u.prev.reportVersion == u.version && u.prev.marker == u.marker {
		p.current[key] = *u.prev

		return nil
	}

	if held {
		p.keepRejected(log, u)

		return nil
	}

	used, err := r.workloadReport(ctx, p, key, report, workload)
	if err != nil {
		return err
	}

	if used != "" {
		p.logIgnored(ctx, key.title, used, report.GetName())

		return nil
	}

	return r.upload(ctx, dd, p, dest, u, workload)
}

// upload reimports the report unless its test already holds it, and remembers the result. A reimport that creates the
// test is followed by the update of its build_id.
func (r *Reconciler) upload(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	dest trivy.Reimport,
	u reportUpload,
	workload trivy.Workload,
) error {
	log := ctrl.LoggerFrom(ctx).WithValues("report", u.report.GetName(), "kind", u.report.GetKind())

	test, exists, err := r.locateTest(ctx, dd, p, u)
	if err != nil {
		return err
	}

	if exists && test.BuildID == u.marker {
		entry := reimportedReport{reportVersion: u.version, marker: u.marker, testID: test.ID}
		p.current[u.key] = entry

		r.recordReimport(p.target.Namespace, u.key, entry)

		log.V(1).Info("Skipped a report that DefectDojo already holds", "test", test.ID)

		return nil
	}

	entry, err := r.uploadReport(ctx, dd, p, dest, u, workload, exists)
	if err != nil {
		return r.uploadFailed(ctx, p, u, err)
	}

	if !exists {
		if err = dd.SetBuildID(ctx, entry.testID, u.marker); err != nil {
			return r.markerFailed(ctx, p, entry.testID, err)
		}
	}

	p.current[u.key] = entry

	r.recordReimport(p.target.Namespace, u.key, entry)

	log.Info("Reimported a report", "product", dest.Product, "engagement", dest.Engagement, "test", entry.testID)

	return nil
}

// skipReport reports whether the fields of the report alone rule out its reimport: it is marked for deletion, broken
// or expired.
func skipReport(log logr.Logger, report *unstructured.Unstructured) bool {
	if report.GetDeletionTimestamp() != nil {
		return true
	}

	if reason := trivy.BrokenReport(report); reason != "" {
		log.Info("Skipped a broken report", "reason", reason)

		return true
	}

	if trivy.ExpiredReport(report) {
		log.V(1).Info("Skipped a report that Trivy Operator deletes at once")

		return true
	}

	return false
}

// currentWorkload returns the stable workload of a report that describes it as it is now and the image reference of
// the container of the report in its pod template. ok is false, without an error, when the report is not reimported
// for that reason.
func (r *Reconciler) currentWorkload(
	ctx context.Context,
	p *pass,
	report *unstructured.Unstructured,
) (workload trivy.Workload, image string, ok bool, err error) {
	log := ctrl.LoggerFrom(ctx).WithValues("report", report.GetName(), "kind", report.GetKind())

	workload, state, err := p.resolver.ResolveReport(ctx, report)
	if err != nil {
		return trivy.Workload{}, "", false, err
	}

	switch state {
	case trivy.WorkloadGone:
		log.V(1).Info("Skipped a report of a workload that is gone", "workload", workload.String())

		return workload, "", false, nil
	case trivy.WorkloadSuperseded:
		log.V(1).Info("Skipped a report of a superseded revision", "workload", workload.String())

		return workload, "", false, nil
	case trivy.WorkloadUnsupported:
		log.V(1).Info("Skipped a report of a resource kind the operator does not read", "workload", workload.String())

		return workload, "", false, nil
	case trivy.WorkloadCurrent:
		// The container is checked below.
	}

	containers, _, err := p.resolver.Containers(ctx, workload)
	if err != nil {
		return trivy.Workload{}, "", false, fmt.Errorf("failed to read the containers of %s: %w", workload, err)
	}

	container := trivy.ContainerOf(report)

	image, in := containers[container]
	if !in {
		log.V(1).Info("Skipped a report of a container that is not in the pod template",
			"workload", workload.String(), "container", container)

		return workload, "", false, nil
	}

	return workload, image, true, nil
}

// namesWorkload reports whether the report is on the stable workload itself, not on a ReplicaSet or Job of it.
func namesWorkload(report *unstructured.Unstructured, workload trivy.Workload) bool {
	return strings.EqualFold(report.GetLabels()[trivy.LabelResourceKind], workload.Kind)
}

// choose makes the report the chosen report of its test, unless another current report of the same test comes
// first. The report that loses is logged.
func (p *pass) choose(ctx context.Context, key testKey, mine choice) bool {
	held, taken := p.chosen[key]
	if !taken || mine.before(held) {
		if taken {
			p.logIgnored(ctx, key.title, mine.report, held.report)
		}

		p.chosen[key] = mine

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

// keepRejected leaves the test of a report version that DefectDojo rejected as it is.
func (p *pass) keepRejected(log logr.Logger, u reportUpload) {
	p.reject(u, *u.rejection)

	log.V(1).Info("Skipped a report version that DefectDojo rejected")
}

// uploadFailed handles a failed upload. A rejection by DefectDojo holds for the report version until the retry after
// resyncPeriod: it is remembered at once, logged at Error and counted once per version. Any other failure leaves the
// result in DefectDojo unknown: the operator closes nothing for the report, keeps the error for the end of the pass
// and uploads the report again in the next pass. The remembered rejection of the version, if any, stays as it is.
func (r *Reconciler) uploadFailed(ctx context.Context, p *pass, u reportUpload, err error) error {
	if !defectdojo.IsRejectedReport(err) {
		if ctx.Err() != nil {
			return err
		}

		p.uploadErrors = append(p.uploadErrors, err)

		if u.rejection != nil {
			p.reject(u, *u.rejection)
		}

		return nil
	}

	log := ctrl.LoggerFrom(ctx)

	if u.rejection == nil {
		log.Error(err, "DefectDojo rejected a report version", "report", u.report.GetName(), "kind", u.report.GetKind())
		rejectedReports.WithLabelValues(u.report.GetKind()).Inc()
	} else {
		log.V(1).Info("DefectDojo rejected a report version again", "report", u.report.GetName(),
			"kind", u.report.GetKind())
	}

	rec := rejection{version: u.version, at: r.now()}

	r.recordRejection(p.target.Namespace, u.key, rec)
	p.reject(u, rec)

	return nil
}

// markerFailed handles a failed update of the build_id of the test a reimport created. The test holds the report and
// has no marker: the error is kept for the end of the pass, the report is not remembered as reimported and is
// uploaded again in the next pass.
func (r *Reconciler) markerFailed(ctx context.Context, p *pass, testID int, err error) error {
	err = fmt.Errorf("failed to set the upload marker of DefectDojo test %d: %w", testID, err)

	if ctx.Err() != nil {
		return err
	}

	p.uploadErrors = append(p.uploadErrors, err)

	return nil
}

// uploadReport reimports the report of the upload. The upload marker goes with the request only when the test exists:
// DefectDojo saves the build_id of a new test before it reads the report, and a failed reimport must not leave it.
func (r *Reconciler) uploadReport(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	dest trivy.Reimport,
	u reportUpload,
	workload trivy.Workload,
	testExists bool,
) (reimportedReport, error) {
	payload, err := json.Marshal(trivy.Payload(u.report, workload))
	if err != nil {
		return reimportedReport{}, fmt.Errorf("failed to marshal report %s: %w", u.report.GetName(), err)
	}

	buildID := ""
	if testExists {
		buildID = u.marker
	}

	p.uploaded = true

	res, err := dd.Reimport(ctx, dest.Request(r.config.ProductType, r.now(), buildID, payload))
	if err != nil {
		return reimportedReport{}, fmt.Errorf("failed to import report %s: %w", u.report.GetName(), err)
	}

	if res.TestID == 0 {
		return reimportedReport{}, fmt.Errorf("defectdojo did not return a test for report %s", u.report.GetName())
	}

	return reimportedReport{reportVersion: u.version, marker: u.marker, testID: res.TestID}, nil
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

// reimportReports reimports every page of reports of the configured kinds in the namespace; only one page is held at
// a time. The kinds it could not list completely are recorded in the pass.
func (r *Reconciler) reimportReports(ctx context.Context, dd DefectDojo, p *pass) error {
	for _, kind := range r.config.ReportKinds {
		listed, err := r.reimportKind(ctx, dd, p, kind)
		if err != nil {
			return err
		}

		if !listed {
			p.unlisted = append(p.unlisted, kind)
		}
	}

	return nil
}

// reimportKind reimports every page of the reports of one kind in the namespace. The result is false when the cluster
// does not serve the kind, also when it stops serving it while its pages are listed. When the listing starts again
// (see trivy.ListPages) the pass forgets what the earlier listing found, and the reports reimported or rejected
// before are skipped as unchanged.
func (r *Reconciler) reimportKind(ctx context.Context, dd DefectDojo, p *pass, kind string) (bool, error) {
	gvk := trivy.ReportGVK(kind)

	err := trivy.ListPages(ctx, trivy.Listing[*unstructured.UnstructuredList]{
		Reader:    r.reader,
		Namespace: p.target.Namespace,
		What:      kind,
		PageSize:  reportsPageSize,

		KindMayBeUnserved: true,
		NewList: func() *unstructured.UnstructuredList {
			list := &unstructured.UnstructuredList{}
			list.SetGroupVersionKind(gvk.GroupVersion().WithKind(kind + "List"))

			return list
		},
		Each: func(list *unstructured.UnstructuredList) error {
			for i := range list.Items {
				// The item kind is not always set on a list read.
				list.Items[i].SetGroupVersionKind(gvk)
			}

			return r.reimportPage(ctx, dd, p, list.Items)
		},
		Restart: func() { p.forget(kind) },
	})

	switch {
	case errors.Is(err, trivy.ErrKindNotServed):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

// lastReimport returns the report the test reflects; nil when none is known.
func (r *Reconciler) lastReimport(namespace string, key testKey) *reimportedReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.reimported[namespace][key]
	if !ok {
		return nil
	}

	return &entry
}

func (r *Reconciler) recordReimport(namespace string, key testKey, entry reimportedReport) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.reimported, namespace, key, entry)
	delete(r.closed[namespace], entry.testID)
}

// recordRejection remembers a rejected report version at once, so a pass that fails later does not upload it again.
func (r *Reconciler) recordRejection(namespace string, key testKey, rec rejection) {
	r.mu.Lock()
	defer r.mu.Unlock()

	put(r.rejectedVersions, namespace, key, rec)
}

// keepReimported forgets the tests that no current report reflects any more, and the rejected versions of reports that
// are not current. What is remembered about a kind the pass could not list stays.
func (r *Reconciler) keepReimported(namespace string, p *pass) {
	r.mu.Lock()
	defer r.mu.Unlock()

	store(r.reimported, namespace, withUnlisted(p, r.reimported[namespace], p.current))
	store(r.rejectedVersions, namespace, withUnlisted(p, r.rejectedVersions[namespace], p.rejected))
}

// store sets the entries of the namespace, and forgets the namespace when it has none.
func store[V any](m map[string]map[testKey]V, namespace string, entries map[testKey]V) {
	if len(entries) == 0 {
		delete(m, namespace)

		return
	}

	m[namespace] = entries
}

// withUnlisted adds to found the remembered entries of the report kinds the pass could not list, and returns found.
func withUnlisted[V any](p *pass, remembered, found map[testKey]V) map[testKey]V {
	for key, v := range remembered {
		if !p.listed(key.title) {
			found[key] = v
		}
	}

	return found
}

// rejectionOf returns the remembered rejection of the version; nil when the test has none or another version of the
// report was rejected.
func (r *Reconciler) rejectionOf(namespace string, key testKey, version reportVersion) *rejection {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.rejectedVersions[namespace][key]
	if !ok || rec.version != version {
		return nil
	}

	return &rec
}

// retryDue reports whether the rejected version is uploaded again: the next periodic pass after the rejection is.
func (r *Reconciler) retryDue(rec rejection) bool {
	return r.now().Sub(rec.at) >= time.Duration(float64(r.config.ResyncPeriod)*(1-resyncJitter))
}

// isRejected reports whether the version was rejected and is not due for a retry.
func (r *Reconciler) isRejected(namespace string, key testKey, version reportVersion) bool {
	rec := r.rejectionOf(namespace, key, version)

	return rec != nil && !r.retryDue(*rec)
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

	delete(r.reimported, namespace)
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
