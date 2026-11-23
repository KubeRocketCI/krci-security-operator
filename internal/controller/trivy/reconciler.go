package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// cache serves the watched Namespaces and the metadata of the watched report kinds.
	cache client.Reader
	// reader reads without a cache: report bodies, the metadata of report kinds that are not watched, workloads and
	// the credentials Secret.
	reader client.Reader
	// watched holds the report kinds watched at start; only their metadata is listed from the cache.
	watched []string
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
	// facts holds, per namespace, the facts of the report versions whose body was read, see keepFacts.
	facts map[string]map[reportVersion]versionFacts

	// productTypeLogged guards the one Info log of a Product Type that DefectDojo does not list.
	productTypeLogged sync.Once

	credMu       sync.Mutex
	creds        credentials
	credsAt      time.Time
	credsValid   bool
	secretLogged bool
}

// NewReconciler returns a Reconciler. cache serves Namespaces and the metadata of the watched report kinds, reader
// serves everything else.
func NewReconciler(cache, reader client.Reader, cfg Config, watched []string, connect Connector) *Reconciler {
	return &Reconciler{
		cache:      cache,
		reader:     reader,
		watched:    slices.Clone(watched),
		config:     cfg,
		connect:    connect,
		now:        time.Now,
		random:     rand.Float64,
		wake:       make(chan event.GenericEvent, wakeBuffer),
		reimported: map[string]map[testKey]reimportedReport{},
		closed:     map[string]map[int]struct{}{},

		rejectedVersions: map[string]map[testKey]rejection{},
		released:         map[string]struct{}{},
		facts:            map[string]map[reportVersion]versionFacts{},
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

	if err = r.syncNamespace(ctx, dd, r.target(namespace), ns.Labels); err != nil {
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

// pass holds what one pass over a namespace accumulates across its reports.
type pass struct {
	target   trivy.Target
	resolver *trivy.WorkloadResolver
	// reports holds the listed report metadata of the pass.
	reports reportListing
	// bodies reads report bodies and holds the facts of the versions read in the pass.
	bodies *reportBodies
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
	report reportMeta
	// body is the body of the report version, read before the upload; nil until it is read.
	body    *unstructured.Unstructured
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

	p.keepEarlier(u)
}

func (p *pass) keepEarlier(u reportUpload) {
	if u.prev != nil {
		p.current[u.key] = *u.prev
	}
}

// listed reports whether the pass listed every report of the kind of the test title.
func (p *pass) listed(title string) bool {
	return !slices.Contains(p.unlisted, trivy.TitleKind(title))
}

// syncNamespace reimports the reports of a namespace kind by kind, closes the tests of workloads and
// containers that are gone and makes sure the namespace product has its tags, the label tags of the namespace labels
// included.
// A report that is missing closes nothing. A failed upload keeps its report for the next pass and does not stop
// the other uploads and the closing; its error is returned with the others.
// The facts of the report versions are kept at the end of every pass, also one that fails or panics.
func (r *Reconciler) syncNamespace(
	ctx context.Context,
	dd DefectDojo,
	target trivy.Target,
	labels map[string]string,
) error {
	p := &pass{
		target: target,
		resolver: trivy.NewWorkloadResolver(r.reader, target.Namespace, r.config.ComponentPrefixes,
			r.config.WorkloadLabelTags),
		reports:  newReportListing(),
		bodies:   newReportBodies(r.reader, target.Namespace, r.knownFacts(target.Namespace)),
		current:  map[testKey]reimportedReport{},
		chosen:   map[testKey]choice{},
		rejected: map[testKey]rejection{},
		ignored:  map[ignoredReport]struct{}{},
	}

	defer r.keepFacts(target.Namespace, p)

	if err := r.reimportReports(ctx, dd, p); err != nil {
		return errors.Join(append(p.uploadErrors, err)...)
	}

	r.keepFacts(target.Namespace, p)

	// The close builds its own lists, see expectedTitles, and reads no report.
	p.resolver, p.reports, p.bodies = nil, reportListing{}, nil

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

	tagsErr := r.setProductTags(ctx, dd, target.Namespace, remote.product, r.config.NamespaceLabelTags, labels)

	return errors.Join(append(p.uploadErrors, closeErr, tagsErr)...)
}

// candidate is a current report with its workload, its test and what is remembered about the test.
type candidate struct {
	workload trivy.Workload
	// ref is the image reference of the container of the report in the pod template of the workload.
	ref       string
	component string
	labelTags []string
	mine      choice
	// held is true when the version is a rejected version whose retry is not due.
	held bool
	u    reportUpload
}

// reimportOne decides on one report and reimports it when it is chosen and changed. A report is not reimported when
// it is marked for deletion, broken or expired, of a workload that is gone, superseded or of a kind the operator does
// not read, of a container that is not in the pod template of its workload, gone at its read, or when another current
// report of the same test comes first.
// The facts of an unknown version are read before the choice, so a broken report takes no choice. carried is the body
// of the record version when a read of the same pass returned it.
// A report version DefectDojo rejects is remembered, see Reconciler.rejectedVersions, and does not fail the pass.
func (r *Reconciler) reimportOne(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	rec reportMeta,
	carried *unstructured.Unstructured,
) error {
	log := ctrl.LoggerFrom(ctx).WithValues("report", rec.obj.GetName(), "kind", rec.kind)

	if skipReport(log, rec.obj) {
		return nil
	}

	c, ok, err := r.candidateOf(ctx, p, rec)
	if err != nil || !ok {
		return err
	}

	// A workload report of a held rejected version is not a current report: it takes no choice of the test.
	if c.held && c.mine.onWorkload {
		p.keepRejected(log, c.u)

		return nil
	}

	f, read, body, err := p.bodies.facts(ctx, rec)
	if err != nil {
		return err
	}

	if read != sameVersion {
		return r.redecide(ctx, dd, p, rec, read, body)
	}

	if f.broken != "" {
		log.Info("Skipped a broken report", "reason", f.broken)

		return nil
	}

	if body == nil {
		body = carried
	}

	c.u.body = body

	return r.chooseAndUpload(ctx, dd, p, log, c, f)
}

// redecide adopts a read that returned another version or found the report gone. Another version is decided again
// from the first rule with the body of the read: the pass holds the facts of the read version, so that run sends no
// GET and decides once. A report that is gone is not current.
func (r *Reconciler) redecide(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	rec reportMeta,
	read readResult,
	body *unstructured.Unstructured,
) error {
	next, ok := p.reports.adopt(rec.kind, rec.obj.GetName(), read, body)
	if !ok {
		ctrl.LoggerFrom(ctx).V(1).Info("Skipped a report that is gone", "report", rec.obj.GetName(), "kind", rec.kind)

		return nil
	}

	return r.reimportOne(ctx, dd, p, next, body)
}

// candidateOf returns the report as a candidate of its test; ok is false, without an error, when it does not describe
// a workload as it is now.
func (r *Reconciler) candidateOf(ctx context.Context, p *pass, rec reportMeta) (candidate, bool, error) {
	workload, ref, ok, err := r.currentWorkload(ctx, p, rec)
	if err != nil || !ok {
		return candidate{}, false, err
	}

	component, err := p.resolver.Component(ctx, workload)
	if err != nil {
		return candidate{}, false, err
	}

	labelTags, err := p.resolver.LabelTags(ctx, workload)
	if err != nil {
		return candidate{}, false, err
	}

	// The layout does not depend on the image.
	key := keyOf(trivy.NewReimport(p.target, rec.kind, rec.obj, workload, component, trivy.Image{}, labelTags))

	u := reportUpload{report: rec, key: key, version: versionOf(rec.obj)}
	u.prev = r.lastReimport(p.target.Namespace, key)
	u.rejection = r.rejectionOf(p.target.Namespace, key, u.version)

	return candidate{
		workload:  workload,
		ref:       ref,
		component: component,
		labelTags: labelTags,
		mine:      choice{report: rec.obj.GetName(), onWorkload: namesWorkload(rec.obj, workload)},
		held:      u.rejection != nil && !r.retryDue(*u.rejection),
		u:         u,
	}, true, nil
}

func keyOf(dest trivy.Reimport) testKey {
	return testKey{product: dest.Product, engagement: dest.Engagement, title: dest.TestTitle}
}

// chooseAndUpload makes the report the chosen report of its test and uploads it unless its test holds it, its version
// is held as rejected, or a report on its stable workload comes first.
func (r *Reconciler) chooseAndUpload(
	ctx context.Context,
	dd DefectDojo,
	p *pass,
	log logr.Logger,
	c candidate,
	f versionFacts,
) error {
	u := c.u

	if !p.choose(ctx, u.key, c.mine) {
		return nil
	}

	dest := trivy.NewReimport(p.target, u.report.kind, u.report.obj, c.workload, c.component, f.image.For(c.ref),
		c.labelTags)
	u.marker = dest.UploadMarker(u.report.obj)

	if u.prev != nil && u.prev.reportVersion == u.version && u.prev.marker == u.marker {
		p.current[u.key] = *u.prev

		return nil
	}

	if c.held {
		p.keepRejected(log, u)

		return nil
	}

	used, err := r.workloadReport(ctx, p, u.key, u.report, c.workload)
	if err != nil {
		return err
	}

	if used != "" {
		p.logIgnored(ctx, u.key.title, used, u.report.obj.GetName())

		return nil
	}

	return r.upload(ctx, dd, p, dest, u, c.workload)
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
	log := ctrl.LoggerFrom(ctx).WithValues("report", u.report.obj.GetName(), "kind", u.report.kind)

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

	if ok, err := r.readForUpload(ctx, p, log, &u); err != nil || !ok {
		return err
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

// readForUpload reads the body of the upload unless it is in hand. ok is false, without an error, when the read
// returned another version or found the report gone: the marker names the listed version, so nothing is uploaded in
// this pass and the test keeps what it reflects. The pass that the change wakes imports it.
func (r *Reconciler) readForUpload(ctx context.Context, p *pass, log logr.Logger, u *reportUpload) (bool, error) {
	if u.body != nil {
		return true, nil
	}

	body, read, err := p.bodies.bodyFor(ctx, u.report)
	if err != nil {
		return false, err
	}

	if read != sameVersion {
		p.reports.adopt(u.report.kind, u.report.obj.GetName(), read, body)
		p.keepEarlier(*u)

		log.V(1).Info("Skipped the upload of a report that changed after it was listed", "read", read.String())

		return false, nil
	}

	u.body = body

	return true, nil
}

// skipReport reports whether the metadata of the report alone rules out its reimport: it is marked for deletion,
// names no test or expired.
func skipReport(log logr.Logger, report metav1.Object) bool {
	if report.GetDeletionTimestamp() != nil {
		return true
	}

	if reason := trivy.BrokenLabels(report); reason != "" {
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
// the container of the report in its pod template, which is not a trivy.Image. ok is false, without an error, when
// the report is not reimported for that reason.
func (r *Reconciler) currentWorkload(
	ctx context.Context,
	p *pass,
	rec reportMeta,
) (workload trivy.Workload, ref string, ok bool, err error) {
	log := ctrl.LoggerFrom(ctx).WithValues("report", rec.obj.GetName(), "kind", rec.kind)

	workload, state, err := p.resolver.ResolveReport(ctx, rec.obj)
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

	container := trivy.ContainerOf(rec.obj)

	ref, in := containers[container]
	if !in {
		log.V(1).Info("Skipped a report of a container that is not in the pod template",
			"workload", workload.String(), "container", container)

		return workload, "", false, nil
	}

	return workload, ref, true, nil
}

// namesWorkload reports whether the report is on the stable workload itself, not on a ReplicaSet or Job of it.
func namesWorkload(report metav1.Object, workload trivy.Workload) bool {
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
		log.Error(err, "DefectDojo rejected a report version", "report", u.report.obj.GetName(), "kind", u.report.kind)
		rejectedReports.WithLabelValues(u.report.kind).Inc()
	} else {
		log.V(1).Info("DefectDojo rejected a report version again", "report", u.report.obj.GetName(),
			"kind", u.report.kind)
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
	payload, err := json.Marshal(trivy.Payload(u.body, workload))
	if err != nil {
		return reimportedReport{}, fmt.Errorf("failed to marshal report %s: %w", u.report.obj.GetName(), err)
	}

	buildID := ""
	if testExists {
		buildID = u.marker
	}

	p.uploaded = true

	res, err := dd.Reimport(ctx, dest.Request(r.config.ProductType, r.now(), buildID, payload))
	if err != nil {
		return reimportedReport{}, fmt.Errorf("failed to import report %s: %w", u.report.obj.GetName(), err)
	}

	if res.TestID == 0 {
		return reimportedReport{}, fmt.Errorf("defectdojo did not return a test for report %s", u.report.obj.GetName())
	}

	return reimportedReport{reportVersion: u.version, marker: u.marker, testID: res.TestID}, nil
}

// reimportReports lists and reimports the reports of the configured kinds in the namespace, kind by kind. The kinds
// the cluster does not serve are recorded in the pass.
func (r *Reconciler) reimportReports(ctx context.Context, dd DefectDojo, p *pass) error {
	for _, kind := range r.config.ReportKinds {
		if err := ctx.Err(); err != nil {
			return err
		}

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

// reimportKind lists the metadata of the reports of one kind in the namespace completely, then decides on them in
// report name order. The result is false when the cluster does not serve the kind, also when it stops serving it
// while its pages are listed. A report that a read of the pass found gone is skipped.
func (r *Reconciler) reimportKind(ctx context.Context, dd DefectDojo, p *pass, kind string) (bool, error) {
	listed, err := r.listReports(ctx, p, kind)
	if err != nil || !listed {
		return false, err
	}

	for _, name := range p.reports.worklist[kind] {
		rec, ok := p.reports.record(kind, name)
		if !ok {
			continue
		}

		if err = r.reimportOne(ctx, dd, p, rec, nil); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (r *Reconciler) knownFacts(namespace string) func(reportVersion) (versionFacts, bool) {
	return func(version reportVersion) (versionFacts, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()

		f, ok := r.facts[namespace][version]

		return f, ok
	}
}

// keepFacts keeps the facts of the namespace for the next pass, once per pass: a pass whose facts are kept has no
// bodies. A kind whose listing completed in the pass keeps the facts of the versions of its records only: the listed
// version, or the one a read returned instead. Any other kind keeps the facts kept before and those read in the pass.
func (r *Reconciler) keepFacts(namespace string, p *pass) {
	if p.bodies == nil {
		return
	}

	effective := p.reports.versions()

	r.mu.Lock()
	defer r.mu.Unlock()

	kept := map[reportVersion]versionFacts{}

	for _, facts := range []map[reportVersion]versionFacts{r.facts[namespace], p.bodies.read} {
		for version, f := range facts {
			if _, ok := effective[version]; ok || !p.reports.isCompleted(f.kind) {
				kept[version] = f
			}
		}
	}

	if len(kept) == 0 {
		delete(r.facts, namespace)

		return
	}

	r.facts[namespace] = kept
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
	delete(r.facts, namespace)
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
