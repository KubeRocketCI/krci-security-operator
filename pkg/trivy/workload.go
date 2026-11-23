package trivy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	kindReplicaSet = "ReplicaSet"
	kindDeployment = "Deployment"
	kindJob        = "Job"
	kindCronJob    = "CronJob"

	// Lower-case workload kinds as they appear in test titles and tags.
	workloadDeployment  = "deployment"
	workloadReplicaSet  = "replicaset"
	workloadStatefulSet = "statefulset"
	workloadDaemonSet   = "daemonset"
	workloadCronJob     = "cronjob"
	workloadJob         = "job"
	workloadPod         = "pod"

	// workloadPageSize is the number of workload objects or Pod metadata objects read per list call.
	workloadPageSize = 500
	// revisionAnnotation is set by the Deployment controller on a Deployment and on its current ReplicaSet.
	revisionAnnotation = "deployment.kubernetes.io/revision"
)

// ErrUnsupportedKind means the operator does not read the workloads of a kind.
var ErrUnsupportedKind = errors.New("workload kind is not supported")

// WorkloadState tells whether the workload a report belongs to is current.
type WorkloadState int

const (
	// WorkloadGone means the workload does not exist: its report is history. A workload scaled to zero is not gone.
	WorkloadGone WorkloadState = iota
	// WorkloadSuperseded means the workload exists but a newer revision is current:
	// the report must not overwrite what the current revision reported.
	WorkloadSuperseded
	// WorkloadCurrent means the report describes the workload as it is defined now. It does not require running
	// pods: environments are scaled to zero while asleep, and closing their findings would make them flap on every
	// sleep and wake.
	WorkloadCurrent
	// WorkloadUnsupported means the workload is of a kind the operator does not read, a ReplicationController for
	// example: its report is not imported.
	WorkloadUnsupported
)

// Workload is the stable identity of a workload: a Deployment for its ReplicaSets, so a rollout
// keeps writing to the same DefectDojo test.
type Workload struct {
	Kind string
	Name string
}

func (w Workload) String() string { return w.Kind + "/" + w.Name }

// Tag is the workload in the form allowed in a DefectDojo tag value.
func (w Workload) Tag() string { return w.Kind + "." + w.Name }

// WorkloadResolver maps the resource a report was produced for to a Workload.
// It lists each kind of workload of the namespace at most once, in pages, and reads each Pod at most once. It keeps
// of every object only what it decides with: owner, revision, creation time, the image reference of each
// container, the component of a stable workload and the tags of its labels for the listed keys; no other labels or
// annotations. Its lists are a snapshot: it is meant to live for one decision, not across a long pass.
type WorkloadResolver struct {
	reader            client.Reader
	namespace         string
	componentPrefixes []string
	labelKeys         []string

	loaded      bool
	replicaSets map[string]replicaSetInfo
	deployments map[string]deploymentInfo

	jobsLoaded bool
	jobs       map[string]jobInfo
	// latestJob holds, per CronJob, the newest Job: the only one whose report is current.
	latestJob map[string]newestJob

	// templateNames holds, per listed kind of templateKinds, the names of its workloads.
	templateNames map[string][]string

	// podSpecs holds what the resolver found out about each workload.
	podSpecs map[Workload]podSpec
}

// podSpec is the pod specification of a workload, as far as the operator reads it.
type podSpec struct {
	found      bool
	containers map[string]string
	// component is the app tag value; "" when no source names one.
	component string
	// labelTags are the label tags of the object the component is read from.
	labelTags []string
}

// replicaSetInfo is what the resolver keeps of a ReplicaSet. spec is set only without a Deployment, and has no
// component.
type replicaSetInfo struct {
	deployment string
	revision   string
	spec       podSpec
}

// deploymentInfo is what the resolver keeps of a Deployment.
type deploymentInfo struct {
	revision string
	spec     podSpec
}

// jobInfo is what the resolver keeps of a Job. spec is set only without a CronJob.
type jobInfo struct {
	cronJob string
	spec    podSpec
}

// newestJob identifies the newest Job of a CronJob.
type newestJob struct {
	name    string
	created metav1.Time
}

// newerThan reports whether the Job is newer than other: by creation time, then by name.
func (j newestJob) newerThan(other newestJob) bool {
	if !j.created.Equal(&other.created) {
		return other.created.Before(&j.created)
	}

	return j.name > other.name
}

// templateKinds are the workload kinds that are listed in pages and kept as container images and the component only.
var templateKinds = []string{workloadStatefulSet, workloadDaemonSet, workloadCronJob}

// NewWorkloadResolver returns a resolver that reads the workloads of namespace. componentPrefixes are stripped from
// the Argo CD application name of a component, see Component. labelKeys are the workload label keys that give label
// tags, see LabelTags.
func NewWorkloadResolver(
	reader client.Reader,
	namespace string,
	componentPrefixes, labelKeys []string,
) *WorkloadResolver {
	return &WorkloadResolver{
		reader:            reader,
		namespace:         namespace,
		componentPrefixes: componentPrefixes,
		labelKeys:         labelKeys,
		templateNames:     map[string][]string{},
		podSpecs:          map[Workload]podSpec{},
	}
}

// ResolveReport returns the workload of a report, see ResourceRef and Resolve.
func (r *WorkloadResolver) ResolveReport(ctx context.Context, report metav1.Object) (Workload, WorkloadState, error) {
	kind, name := ResourceRef(report)

	return r.Resolve(ctx, kind, name)
}

// Resolve returns the workload of a report's resource kind and name and whether it is current.
// ReplicaSets resolve to their Deployment and Jobs to their CronJob; every other kind is its own workload.
// A workload that does not exist is gone; its replica count never decides the state: a sleeping environment keeps
// its findings.
func (r *WorkloadResolver) Resolve(ctx context.Context, kind, name string) (Workload, WorkloadState, error) {
	var (
		w     Workload
		state WorkloadState
		err   error
	)

	switch kind {
	case kindReplicaSet:
		w, state, err = r.resolveReplicaSet(ctx, name)
	case kindJob:
		w, state, err = r.resolveJob(ctx, name)
	default:
		w, state = Workload{Kind: strings.ToLower(kind), Name: name}, WorkloadCurrent
	}

	if err != nil {
		return Workload{}, WorkloadGone, err
	}

	if state == WorkloadGone {
		return w, state, nil
	}

	_, found, err := r.Containers(ctx, w)

	switch {
	case errors.Is(err, ErrUnsupportedKind):
		return w, WorkloadUnsupported, nil
	case err != nil:
		return Workload{}, WorkloadGone, err
	case !found:
		return w, WorkloadGone, nil
	}

	return w, state, nil
}

// Containers returns the containers in the pod specification of the workload, by name, each with its image reference
// as written in the specification: containers, init containers and, for a Pod, ephemeral containers. The reference
// is "" for a container without an image. found is false when the workload does not exist.
// The error is ErrUnsupportedKind for a workload kind the operator does not read.
func (r *WorkloadResolver) Containers(
	ctx context.Context,
	w Workload,
) (containers map[string]string, found bool, err error) {
	spec, err := r.spec(ctx, w)
	if err != nil {
		return nil, false, err
	}

	return spec.containers, spec.found, nil
}

// Component returns the app tag value of a workload, derived by the package function Component from the labels and
// annotations of a Deployment, StatefulSet, DaemonSet, CronJob or Job in its list, of a Pod from its Get. It is ""
// for a ReplicaSet, a workload that does not exist and a kind the operator does not read.
func (r *WorkloadResolver) Component(ctx context.Context, w Workload) (string, error) {
	spec, err := r.knownSpec(ctx, w)

	return spec.component, err
}

// LabelTags returns the tags of the labels of a workload for the listed keys, see the package function LabelTags. The
// labels are those of the object the component is read from, see Component: the top workload object, not the
// ReplicaSet of a Deployment or the Job of a CronJob. It is empty for a ReplicaSet without a Deployment, a workload
// that does not exist and a kind the operator does not read.
func (r *WorkloadResolver) LabelTags(ctx context.Context, w Workload) ([]string, error) {
	spec, err := r.knownSpec(ctx, w)

	return spec.labelTags, err
}

// knownSpec returns the pod specification of a workload like spec, and an empty one for a kind the operator does not
// read.
func (r *WorkloadResolver) knownSpec(ctx context.Context, w Workload) (podSpec, error) {
	spec, err := r.spec(ctx, w)
	if errors.Is(err, ErrUnsupportedKind) {
		return podSpec{}, nil
	}

	return spec, err
}

// spec returns the pod specification of a workload, read at most once per resolver.
func (r *WorkloadResolver) spec(ctx context.Context, w Workload) (podSpec, error) {
	if spec, ok := r.podSpecs[w]; ok {
		return spec, nil
	}

	spec, err := r.readSpec(ctx, w)
	if err != nil {
		return podSpec{}, err
	}

	r.podSpecs[w] = spec

	return spec, nil
}

// specOf returns the pod specification of a workload object that exists, with its component and label tags.
func (r *WorkloadResolver) specOf(obj metav1.Object, template *corev1.PodSpec) podSpec {
	return podSpec{
		found:      true,
		containers: containerImages(template),
		component:  Component(obj.GetLabels(), obj.GetAnnotations(), r.componentPrefixes),
		labelTags:  LabelTags(r.labelKeys, obj.GetLabels()),
	}
}

// StableWorkloads returns every workload of the namespace that a report can be imported for: Deployments,
// ReplicaSets without a Deployment, StatefulSets, DaemonSets, CronJobs, Jobs without a CronJob and Pods without a
// controller. Its containers are then known to Containers. A workload scaled to zero is among them. The order is not
// fixed.
func (r *WorkloadResolver) StableWorkloads(ctx context.Context) ([]Workload, error) {
	out, err := r.loadedWorkloads(ctx)
	if err != nil {
		return nil, err
	}

	for _, kind := range templateKinds {
		if err = r.loadTemplates(ctx, kind); err != nil {
			return nil, err
		}

		for _, name := range r.templateNames[kind] {
			out = append(out, Workload{Kind: kind, Name: name})
		}
	}

	pods, err := r.barePods(ctx)
	if err != nil {
		return nil, err
	}

	return append(out, pods...), nil
}

// remember records the pod specification of a workload and returns the workload.
func (r *WorkloadResolver) remember(kind, name string, spec podSpec) Workload {
	w := Workload{Kind: kind, Name: name}
	r.podSpecs[w] = spec

	return w
}

// loadedWorkloads returns the stable Deployments, ReplicaSets and Jobs of the lists the resolver holds.
func (r *WorkloadResolver) loadedWorkloads(ctx context.Context) ([]Workload, error) {
	if err := r.load(ctx); err != nil {
		return nil, err
	}

	if err := r.loadJobs(ctx); err != nil {
		return nil, err
	}

	var out []Workload

	for name, d := range r.deployments {
		out = append(out, r.remember(workloadDeployment, name, d.spec))
	}

	for name, rs := range r.replicaSets {
		if rs.deployment == "" {
			out = append(out, r.remember(workloadReplicaSet, name, rs.spec))
		}
	}

	for name, job := range r.jobs {
		if job.cronJob == "" {
			out = append(out, r.remember(workloadJob, name, job.spec))
		}
	}

	return out, nil
}

// loadTemplates lists the workloads of a kind in pages, once per resolver, and keeps their names, containers and
// components.
func (r *WorkloadResolver) loadTemplates(ctx context.Context, kind string) error {
	if _, ok := r.templateNames[kind]; ok {
		return nil
	}

	var (
		found []templateWorkload
		err   error
	)

	what, restart := kind+" workloads", func() { found = nil }

	switch kind {
	case workloadStatefulSet:
		err = ListPages(ctx, workloadListing(r, what, restart,
			func() *appsv1.StatefulSetList { return &appsv1.StatefulSetList{} },
			func(list *appsv1.StatefulSetList) error {
				for i := range list.Items {
					found = append(found, r.listed(&list.Items[i], &list.Items[i].Spec.Template.Spec))
				}

				return nil
			}))
	case workloadDaemonSet:
		err = ListPages(ctx, workloadListing(r, what, restart,
			func() *appsv1.DaemonSetList { return &appsv1.DaemonSetList{} },
			func(list *appsv1.DaemonSetList) error {
				for i := range list.Items {
					found = append(found, r.listed(&list.Items[i], &list.Items[i].Spec.Template.Spec))
				}

				return nil
			}))
	case workloadCronJob:
		err = ListPages(ctx, workloadListing(r, what, restart,
			func() *batchv1.CronJobList { return &batchv1.CronJobList{} },
			func(list *batchv1.CronJobList) error {
				for i := range list.Items {
					found = append(found, r.listed(&list.Items[i], &list.Items[i].Spec.JobTemplate.Spec.Template.Spec))
				}

				return nil
			}))
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedKind, kind)
	}

	if err != nil {
		return err
	}

	names := make([]string, 0, len(found))
	for _, w := range found {
		names = append(names, r.remember(kind, w.name, w.spec).Name)
	}

	r.templateNames[kind] = names

	return nil
}

// templateWorkload is a workload of a template kind as the listing delivers it.
type templateWorkload struct {
	name string
	spec podSpec
}

func (r *WorkloadResolver) listed(obj metav1.Object, template *corev1.PodSpec) templateWorkload {
	return templateWorkload{name: obj.GetName(), spec: r.specOf(obj, template)}
}

// workloadListing returns the paged listing of the workload objects of the namespace of the resolver.
func workloadListing[L client.ObjectList](
	r *WorkloadResolver,
	what string,
	restart func(),
	newList func() L,
	each func(L) error,
) Listing[L] {
	return Listing[L]{
		Reader: r.reader, Namespace: r.namespace, What: what, PageSize: workloadPageSize,
		NewList: newList, Each: each, Restart: restart,
	}
}

// barePods returns the Pods without a controller. Their metadata is listed in pages; the containers of each are
// read with a Get.
func (r *WorkloadResolver) barePods(ctx context.Context) ([]Workload, error) {
	var names []string

	err := ListPages(ctx, workloadListing(r, "Pods", func() { names = nil },
		func() *metav1.PartialObjectMetadataList {
			list := &metav1.PartialObjectMetadataList{}
			list.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("PodList"))

			return list
		},
		func(list *metav1.PartialObjectMetadataList) error {
			for i := range list.Items {
				if metav1.GetControllerOf(&list.Items[i]) == nil {
					names = append(names, list.Items[i].Name)
				}
			}

			return nil
		}))
	if err != nil {
		return nil, err
	}

	var out []Workload

	for _, name := range names {
		w := Workload{Kind: workloadPod, Name: name}

		_, found, err := r.Containers(ctx, w)
		if err != nil {
			return nil, err
		}

		if found {
			out = append(out, w)
		}
	}

	return out, nil
}

// readSpec reads the pod specification of a workload that the resolver has not seen yet. Deployments, ReplicaSets,
// Jobs, StatefulSets, DaemonSets and CronJobs come from the lists the resolver holds; a Pod is read with a Get.
func (r *WorkloadResolver) readSpec(ctx context.Context, w Workload) (podSpec, error) {
	switch w.Kind {
	case workloadDeployment:
		return r.deploymentSpec(ctx, w.Name)
	case workloadReplicaSet:
		return r.replicaSetSpec(ctx, w.Name)
	case workloadJob:
		return r.jobSpec(ctx, w.Name)
	case workloadStatefulSet, workloadDaemonSet, workloadCronJob:
		if err := r.loadTemplates(ctx, w.Kind); err != nil {
			return podSpec{}, err
		}

		return r.podSpecs[w], nil
	case workloadPod:
		return r.readPod(ctx, w.Name)
	default:
		return podSpec{}, fmt.Errorf("%w: %q", ErrUnsupportedKind, w.Kind)
	}
}

func (r *WorkloadResolver) deploymentSpec(ctx context.Context, name string) (podSpec, error) {
	if err := r.load(ctx); err != nil {
		return podSpec{}, err
	}

	return r.deployments[name].spec, nil
}

// replicaSetSpec finds only a ReplicaSet without a Deployment: the other is not a workload of its own.
func (r *WorkloadResolver) replicaSetSpec(ctx context.Context, name string) (podSpec, error) {
	if err := r.load(ctx); err != nil {
		return podSpec{}, err
	}

	return r.replicaSets[name].spec, nil
}

// jobSpec finds only a Job without a CronJob: the other is not a workload of its own.
func (r *WorkloadResolver) jobSpec(ctx context.Context, name string) (podSpec, error) {
	if err := r.loadJobs(ctx); err != nil {
		return podSpec{}, err
	}

	return r.jobs[name].spec, nil
}

// readPod reads a Pod with a Get; found is false when it does not exist.
func (r *WorkloadResolver) readPod(ctx context.Context, name string) (podSpec, error) {
	pod := &corev1.Pod{}

	if err := r.reader.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: name}, pod); err != nil {
		if k8sErrors.IsNotFound(err) {
			return podSpec{}, nil
		}

		return podSpec{}, fmt.Errorf("failed to get Pod %s: %w", name, err)
	}

	return r.specOf(pod, &pod.Spec), nil
}

// containerImages returns the image reference of every container of the pod specification by container name:
// containers, init containers and ephemeral containers. A container without an image maps to "".
func containerImages(spec *corev1.PodSpec) map[string]string {
	images := map[string]string{}

	if spec == nil {
		return images
	}

	for _, c := range spec.Containers {
		images[c.Name] = c.Image
	}

	for _, c := range spec.InitContainers {
		images[c.Name] = c.Image
	}

	for _, c := range spec.EphemeralContainers {
		images[c.Name] = c.Image
	}

	return images
}

func (r *WorkloadResolver) resolveReplicaSet(ctx context.Context, name string) (Workload, WorkloadState, error) {
	if err := r.load(ctx); err != nil {
		return Workload{}, WorkloadGone, err
	}

	rs, ok := r.replicaSets[name]
	if !ok {
		return Workload{}, WorkloadGone, nil
	}

	if rs.deployment == "" {
		return Workload{Kind: workloadReplicaSet, Name: name}, WorkloadCurrent, nil
	}

	w := Workload{Kind: workloadDeployment, Name: rs.deployment}

	deployment, ok := r.deployments[rs.deployment]
	if !ok {
		return w, WorkloadGone, nil
	}

	if rs.revision != deployment.revision {
		return w, WorkloadSuperseded, nil
	}

	return w, WorkloadCurrent, nil
}

// resolveJob maps a Job owned by a CronJob to the CronJob; only the newest Job of a CronJob is current.
// A Job without a CronJob is its own workload.
// A Job missing from this pass's snapshot is gone for the pass: it may have been created after the snapshot,
// so its CronJob is unknown, and the next pass resolves it.
func (r *WorkloadResolver) resolveJob(ctx context.Context, name string) (Workload, WorkloadState, error) {
	if err := r.loadJobs(ctx); err != nil {
		return Workload{}, WorkloadGone, err
	}

	job, ok := r.jobs[name]
	if !ok {
		return Workload{Kind: workloadJob, Name: name}, WorkloadGone, nil
	}

	if job.cronJob == "" {
		return Workload{Kind: workloadJob, Name: name}, WorkloadCurrent, nil
	}

	w := Workload{Kind: workloadCronJob, Name: job.cronJob}
	if r.latestJob[job.cronJob].name != name {
		return w, WorkloadSuperseded, nil
	}

	return w, WorkloadCurrent, nil
}

func (r *WorkloadResolver) loadJobs(ctx context.Context) error {
	if r.jobsLoaded {
		return nil
	}

	jobs := map[string]jobInfo{}
	latest := map[string]newestJob{}

	err := ListPages(ctx, workloadListing(r, "Jobs", func() { clear(jobs); clear(latest) },
		func() *batchv1.JobList { return &batchv1.JobList{} },
		func(list *batchv1.JobList) error {
			for i := range list.Items {
				job := &list.Items[i]
				info := jobInfo{cronJob: cronJobOwner(job)}

				if info.cronJob == "" {
					info.spec = r.specOf(job, &job.Spec.Template.Spec)
				} else {
					newest := newestJob{name: job.Name, created: job.CreationTimestamp}
					if current, ok := latest[info.cronJob]; !ok || newest.newerThan(current) {
						latest[info.cronJob] = newest
					}
				}

				jobs[job.Name] = info
			}

			return nil
		}))
	if err != nil {
		return err
	}

	r.jobs, r.latestJob, r.jobsLoaded = jobs, latest, true

	return nil
}

func cronJobOwner(job *batchv1.Job) string {
	for _, ref := range job.OwnerReferences {
		if ref.Kind == kindCronJob && ptr.Deref(ref.Controller, false) {
			return ref.Name
		}
	}

	return ""
}

func (r *WorkloadResolver) load(ctx context.Context) error {
	if r.loaded {
		return nil
	}

	// ReplicaSets are listed before Deployments, Jobs before CronJobs: the owner of a listed object is in the later list.
	replicaSets := map[string]replicaSetInfo{}

	err := ListPages(ctx, workloadListing(r, "ReplicaSets", func() { clear(replicaSets) },
		func() *appsv1.ReplicaSetList { return &appsv1.ReplicaSetList{} },
		func(list *appsv1.ReplicaSetList) error {
			for i := range list.Items {
				rs := &list.Items[i]
				info := replicaSetInfo{deployment: deploymentOwner(rs), revision: rs.Annotations[revisionAnnotation]}

				if info.deployment == "" {
					info.spec = podSpec{found: true, containers: containerImages(&rs.Spec.Template.Spec)}
				}

				replicaSets[rs.Name] = info
			}

			return nil
		}))
	if err != nil {
		return err
	}

	deployments := map[string]deploymentInfo{}

	err = ListPages(ctx, workloadListing(r, "Deployments", func() { clear(deployments) },
		func() *appsv1.DeploymentList { return &appsv1.DeploymentList{} },
		func(list *appsv1.DeploymentList) error {
			for i := range list.Items {
				d := &list.Items[i]
				deployments[d.Name] = deploymentInfo{
					revision: d.Annotations[revisionAnnotation],
					spec:     r.specOf(d, &d.Spec.Template.Spec),
				}
			}

			return nil
		}))
	if err != nil {
		return err
	}

	r.replicaSets, r.deployments, r.loaded = replicaSets, deployments, true

	return nil
}

func deploymentOwner(rs *appsv1.ReplicaSet) string {
	for _, ref := range rs.OwnerReferences {
		if ref.Kind == kindDeployment && ptr.Deref(ref.Controller, false) {
			return ref.Name
		}
	}

	return ""
}
