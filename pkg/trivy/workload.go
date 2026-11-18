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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

	groupApps  = "apps"
	groupBatch = "batch"
	// listPageSize is the number of workload objects or Pod metadata objects read per list call.
	listPageSize = 500
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
// of every object only what it decides with: owner, revision, creation time and container names. Its lists are a
// snapshot: it is meant to live for one decision, not across a long pass.
type WorkloadResolver struct {
	reader    client.Reader
	namespace string

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
	containers map[string]struct{}
}

// replicaSetInfo is what the resolver keeps of a ReplicaSet. containers is set only without a Deployment.
type replicaSetInfo struct {
	deployment string
	revision   string
	containers map[string]struct{}
}

// deploymentInfo is what the resolver keeps of a Deployment.
type deploymentInfo struct {
	revision   string
	containers map[string]struct{}
}

// jobInfo is what the resolver keeps of a Job. containers is set only without a CronJob.
type jobInfo struct {
	cronJob    string
	containers map[string]struct{}
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

// templateKinds are the workload kinds that are listed in pages and kept as container names only.
var templateKinds = []string{workloadStatefulSet, workloadDaemonSet, workloadCronJob}

// NewWorkloadResolver returns a resolver that reads the workloads of namespace.
func NewWorkloadResolver(reader client.Reader, namespace string) *WorkloadResolver {
	return &WorkloadResolver{
		reader:        reader,
		namespace:     namespace,
		templateNames: map[string][]string{},
		podSpecs:      map[Workload]podSpec{},
	}
}

// ResolveReport returns the workload of a report, see ResourceRef and Resolve.
func (r *WorkloadResolver) ResolveReport(
	ctx context.Context,
	report *unstructured.Unstructured,
) (Workload, WorkloadState, error) {
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

	if err != nil || state == WorkloadGone {
		return w, state, err
	}

	_, found, err := r.Containers(ctx, w)

	switch {
	case errors.Is(err, ErrUnsupportedKind):
		return w, WorkloadUnsupported, nil
	case err != nil:
		return w, WorkloadGone, err
	case !found:
		return w, WorkloadGone, nil
	}

	return w, state, nil
}

// Containers returns the names of the containers in the pod specification of the workload: containers, init
// containers and, for a Pod, ephemeral containers. found is false when the workload does not exist.
// The error is ErrUnsupportedKind for a workload kind the operator does not read.
func (r *WorkloadResolver) Containers(
	ctx context.Context,
	w Workload,
) (names map[string]struct{}, found bool, err error) {
	if spec, ok := r.podSpecs[w]; ok {
		return spec.containers, spec.found, nil
	}

	names, found, err = r.readContainers(ctx, w)
	if err != nil {
		return nil, false, err
	}

	r.podSpecs[w] = podSpec{found: found, containers: names}

	return names, found, nil
}

// StableWorkloads returns every workload of the namespace that a report can be imported for: Deployments,
// ReplicaSets without a Deployment, StatefulSets, DaemonSets, CronJobs, Jobs without a CronJob and Pods without a
// controller. Its containers are then known to Containers. A workload scaled to zero is among them.
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

// remember records the containers of a workload that exists and returns the workload.
func (r *WorkloadResolver) remember(kind, name string, containers map[string]struct{}) Workload {
	w := Workload{Kind: kind, Name: name}
	r.podSpecs[w] = podSpec{found: true, containers: containers}

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
		out = append(out, r.remember(workloadDeployment, name, d.containers))
	}

	for name, rs := range r.replicaSets {
		if rs.deployment == "" {
			out = append(out, r.remember(workloadReplicaSet, name, rs.containers))
		}
	}

	for name, job := range r.jobs {
		if job.cronJob == "" {
			out = append(out, r.remember(workloadJob, name, job.containers))
		}
	}

	return out, nil
}

// loadTemplates lists the workloads of a kind in pages, once per resolver, and keeps their containers and names.
func (r *WorkloadResolver) loadTemplates(ctx context.Context, kind string) error {
	if _, ok := r.templateNames[kind]; ok {
		return nil
	}

	var (
		names []string
		err   error
	)

	switch kind {
	case workloadStatefulSet:
		err = listPages(ctx, r.reader, r.namespace, func() *appsv1.StatefulSetList { return &appsv1.StatefulSetList{} },
			func(list *appsv1.StatefulSetList) {
				for i := range list.Items {
					spec := &list.Items[i].Spec.Template.Spec
					names = append(names, r.remember(kind, list.Items[i].Name, containerNames(spec)).Name)
				}
			})
	case workloadDaemonSet:
		err = listPages(ctx, r.reader, r.namespace, func() *appsv1.DaemonSetList { return &appsv1.DaemonSetList{} },
			func(list *appsv1.DaemonSetList) {
				for i := range list.Items {
					spec := &list.Items[i].Spec.Template.Spec
					names = append(names, r.remember(kind, list.Items[i].Name, containerNames(spec)).Name)
				}
			})
	case workloadCronJob:
		err = listPages(ctx, r.reader, r.namespace, func() *batchv1.CronJobList { return &batchv1.CronJobList{} },
			func(list *batchv1.CronJobList) {
				for i := range list.Items {
					spec := &list.Items[i].Spec.JobTemplate.Spec.Template.Spec
					names = append(names, r.remember(kind, list.Items[i].Name, containerNames(spec)).Name)
				}
			})
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedKind, kind)
	}

	if err != nil {
		return fmt.Errorf("failed to list %s workloads: %w", kind, err)
	}

	r.templateNames[kind] = names

	return nil
}

// barePods returns the Pods without a controller. Their metadata is listed in pages; the containers of each are
// read with a Get.
func (r *WorkloadResolver) barePods(ctx context.Context) ([]Workload, error) {
	var names []string

	err := listPages(ctx, r.reader, r.namespace,
		func() *metav1.PartialObjectMetadataList {
			list := &metav1.PartialObjectMetadataList{}
			list.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("PodList"))

			return list
		},
		func(list *metav1.PartialObjectMetadataList) {
			for i := range list.Items {
				if metav1.GetControllerOf(&list.Items[i]) == nil {
					names = append(names, list.Items[i].Name)
				}
			}
		})
	if err != nil {
		return nil, fmt.Errorf("failed to list Pods: %w", err)
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

// listPages lists the objects of a namespace page by page and hands each page to each.
func listPages[L client.ObjectList](
	ctx context.Context,
	reader client.Reader,
	namespace string,
	newList func() L,
	each func(L),
) error {
	opts := []client.ListOption{client.InNamespace(namespace), client.Limit(listPageSize)}

	for {
		list := newList()
		if err := reader.List(ctx, list, opts...); err != nil {
			return err
		}

		each(list)

		next := list.GetContinue()
		if next == "" {
			return nil
		}

		opts = []client.ListOption{client.InNamespace(namespace), client.Limit(listPageSize), client.Continue(next)}
	}
}

// readContainers reads the container names of a workload that Containers has not seen yet. Deployments, ReplicaSets,
// Jobs, StatefulSets, DaemonSets and CronJobs come from the lists the resolver holds; a Pod is read with a Get.
func (r *WorkloadResolver) readContainers(ctx context.Context, w Workload) (map[string]struct{}, bool, error) {
	switch w.Kind {
	case workloadDeployment:
		return r.deploymentContainers(ctx, w.Name)
	case workloadReplicaSet:
		return r.replicaSetContainers(ctx, w.Name)
	case workloadJob:
		return r.jobContainers(ctx, w.Name)
	case workloadStatefulSet, workloadDaemonSet, workloadCronJob:
		if err := r.loadTemplates(ctx, w.Kind); err != nil {
			return nil, false, err
		}

		spec, ok := r.podSpecs[w]

		return spec.containers, ok, nil
	case workloadPod:
		return r.podContainers(ctx, w.Name)
	default:
		return nil, false, fmt.Errorf("%w: %q", ErrUnsupportedKind, w.Kind)
	}
}

func (r *WorkloadResolver) deploymentContainers(ctx context.Context, name string) (map[string]struct{}, bool, error) {
	if err := r.load(ctx); err != nil {
		return nil, false, err
	}

	d, ok := r.deployments[name]

	return d.containers, ok, nil
}

// replicaSetContainers finds only a ReplicaSet without a Deployment: the other is not a workload of its own.
func (r *WorkloadResolver) replicaSetContainers(ctx context.Context, name string) (map[string]struct{}, bool, error) {
	if err := r.load(ctx); err != nil {
		return nil, false, err
	}

	rs, ok := r.replicaSets[name]

	return rs.containers, ok && rs.deployment == "", nil
}

// jobContainers finds only a Job without a CronJob: the other is not a workload of its own.
func (r *WorkloadResolver) jobContainers(ctx context.Context, name string) (map[string]struct{}, bool, error) {
	if err := r.loadJobs(ctx); err != nil {
		return nil, false, err
	}

	job, ok := r.jobs[name]

	return job.containers, ok && job.cronJob == "", nil
}

// podContainers reads a Pod with a Get; found is false when it does not exist.
func (r *WorkloadResolver) podContainers(ctx context.Context, name string) (map[string]struct{}, bool, error) {
	pod := &corev1.Pod{}

	if err := r.reader.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: name}, pod); err != nil {
		if k8sErrors.IsNotFound(err) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to get Pod %s: %w", name, err)
	}

	return containerNames(&pod.Spec), true, nil
}

func containerNames(spec *corev1.PodSpec) map[string]struct{} {
	names := map[string]struct{}{}

	if spec == nil {
		return names
	}

	for _, c := range spec.Containers {
		names[c.Name] = struct{}{}
	}

	for _, c := range spec.InitContainers {
		names[c.Name] = struct{}{}
	}

	for _, c := range spec.EphemeralContainers {
		names[c.Name] = struct{}{}
	}

	return names
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

	err := listPages(ctx, r.reader, r.namespace, func() *batchv1.JobList { return &batchv1.JobList{} },
		func(list *batchv1.JobList) {
			for i := range list.Items {
				job := &list.Items[i]
				info := jobInfo{cronJob: cronJobOwner(job)}

				if info.cronJob == "" {
					info.containers = containerNames(&job.Spec.Template.Spec)
				} else {
					newest := newestJob{name: job.Name, created: job.CreationTimestamp}
					if current, ok := latest[info.cronJob]; !ok || newest.newerThan(current) {
						latest[info.cronJob] = newest
					}
				}

				jobs[job.Name] = info
			}
		})
	if err != nil {
		return fmt.Errorf("failed to list Jobs: %w", err)
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

	err := listPages(ctx, r.reader, r.namespace, func() *appsv1.ReplicaSetList { return &appsv1.ReplicaSetList{} },
		func(list *appsv1.ReplicaSetList) {
			for i := range list.Items {
				rs := &list.Items[i]
				info := replicaSetInfo{deployment: deploymentOwner(rs), revision: rs.Annotations[revisionAnnotation]}

				if info.deployment == "" {
					info.containers = containerNames(&rs.Spec.Template.Spec)
				}

				replicaSets[rs.Name] = info
			}
		})
	if err != nil {
		return fmt.Errorf("failed to list ReplicaSets: %w", err)
	}

	deployments := map[string]deploymentInfo{}

	err = listPages(ctx, r.reader, r.namespace, func() *appsv1.DeploymentList { return &appsv1.DeploymentList{} },
		func(list *appsv1.DeploymentList) {
			for i := range list.Items {
				d := &list.Items[i]
				deployments[d.Name] = deploymentInfo{
					revision:   d.Annotations[revisionAnnotation],
					containers: containerNames(&d.Spec.Template.Spec),
				}
			}
		})
	if err != nil {
		return fmt.Errorf("failed to list Deployments: %w", err)
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
