package trivy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "krci-demo-dev"

func newReplicaSet(name, deployment, revision string, replicas int32) *appsv1.ReplicaSet {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   testNamespace,
			Annotations: map[string]string{revisionAnnotation: revision},
		},
		Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To(replicas)},
	}

	if deployment != "" {
		rs.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: deployment, Controller: ptr.To(true),
		}}
	}

	return rs
}

func newDeployment(name, revision string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name:        name,
		Namespace:   testNamespace,
		Annotations: map[string]string{revisionAnnotation: revision},
	}}
}

func TestWorkloadResolver_Resolve(t *testing.T) {
	objects := []client.Object{
		newDeployment("app", "2"),
		newReplicaSet("app-old", "app", "1", 0),
		newReplicaSet("app-new", "app", "2", 3),
		newReplicaSet("owner-gone", "removed", "1", 1),
		newReplicaSet("standalone", "", "", 1),
		newReplicaSet("standalone-scaled-down", "", "", 0),
		newDeployment("asleep", "1"),
		newReplicaSet("asleep-1", "asleep", "1", 0),
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: testNamespace}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: testNamespace}},
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: testNamespace}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: testNamespace}},
	}

	tests := []struct {
		name      string
		kind      string
		resource  string
		want      Workload
		wantState WorkloadState
	}{
		{name: "current revision", kind: "ReplicaSet", resource: "app-new", want: Workload{"deployment", "app"}, wantState: WorkloadCurrent},
		{name: "old revision", kind: "ReplicaSet", resource: "app-old", want: Workload{"deployment", "app"}, wantState: WorkloadSuperseded},
		{name: "replicaset deleted", kind: "ReplicaSet", resource: "missing", wantState: WorkloadGone},
		{name: "deployment deleted", kind: "ReplicaSet", resource: "owner-gone", want: Workload{"deployment", "removed"}, wantState: WorkloadGone},
		{name: "replicaset without deployment", kind: "ReplicaSet", resource: "standalone", want: Workload{"replicaset", "standalone"}, wantState: WorkloadCurrent},
		{name: "replicaset without deployment scaled to zero is not gone", kind: "ReplicaSet", resource: "standalone-scaled-down", want: Workload{"replicaset", "standalone-scaled-down"}, wantState: WorkloadCurrent},
		{name: "deployment scaled to zero stays current", kind: "ReplicaSet", resource: "asleep-1", want: Workload{"deployment", "asleep"}, wantState: WorkloadCurrent},
		{name: "statefulset", kind: "StatefulSet", resource: "db", want: Workload{"statefulset", "db"}, wantState: WorkloadCurrent},
		{name: "statefulset deleted", kind: "StatefulSet", resource: "removed", want: Workload{"statefulset", "removed"}, wantState: WorkloadGone},
		{name: "daemonset", kind: "DaemonSet", resource: "agent", want: Workload{"daemonset", "agent"}, wantState: WorkloadCurrent},
		{name: "daemonset deleted", kind: "DaemonSet", resource: "removed", want: Workload{"daemonset", "removed"}, wantState: WorkloadGone},
		{name: "cronjob", kind: "CronJob", resource: "nightly", want: Workload{"cronjob", "nightly"}, wantState: WorkloadCurrent},
		{name: "cronjob deleted", kind: "CronJob", resource: "removed", want: Workload{"cronjob", "removed"}, wantState: WorkloadGone},
		{name: "pod", kind: "Pod", resource: "debug", want: Workload{"pod", "debug"}, wantState: WorkloadCurrent},
		{name: "pod deleted", kind: "Pod", resource: "removed", want: Workload{"pod", "removed"}, wantState: WorkloadGone},
		{name: "kind the operator does not read", kind: "ReplicationController", resource: "legacy", want: Workload{"replicationcontroller", "legacy"}, wantState: WorkloadUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()

			got, state, err := NewWorkloadResolver(c, testNamespace).Resolve(context.Background(), tt.kind, tt.resource)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantState, state)
		})
	}
}

func TestWorkloadResolver_Resolve_ListsOnce(t *testing.T) {
	lists := 0
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(newDeployment("app", "1"), newReplicaSet("app-1", "app", "1", 1)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				lists++

				return cl.List(ctx, list, opts...)
			},
		}).Build()

	r := NewWorkloadResolver(c, testNamespace)

	for range 3 {
		_, _, err := r.Resolve(context.Background(), "ReplicaSet", "app-1")
		require.NoError(t, err)
	}

	assert.Equal(t, 2, lists)
}

func TestWorkloadResolver_Resolve_ListError(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return assert.AnError
			},
		}).Build()

	_, _, err := NewWorkloadResolver(c, testNamespace).Resolve(context.Background(), "ReplicaSet", "app-1")

	require.ErrorIs(t, err, assert.AnError)
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(s))
	require.NoError(t, batchv1.AddToScheme(s))
	require.NoError(t, corev1.AddToScheme(s))

	return s
}

func newJob(name, cronJob string, age time.Duration) *batchv1.Job {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		Namespace:         testNamespace,
		CreationTimestamp: metav1.NewTime(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC).Add(-age)),
	}}

	if cronJob != "" {
		job.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "batch/v1", Kind: "CronJob", Name: cronJob, Controller: ptr.To(true),
		}}
	}

	return job
}

func TestWorkloadResolver_Resolve_Jobs(t *testing.T) {
	objects := []client.Object{
		newJob("nightly-3", "nightly", 0),
		newJob("nightly-2", "nightly", time.Hour),
		newJob("nightly-1", "nightly", 2*time.Hour),
		newJob("migrate", "", 0),
		newJob("orphan-1", "removed", 0),
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: testNamespace}},
	}

	tests := []struct {
		name      string
		resource  string
		want      Workload
		wantState WorkloadState
	}{
		{name: "newest run is current", resource: "nightly-3", want: Workload{"cronjob", "nightly"}, wantState: WorkloadCurrent},
		{name: "older run is superseded", resource: "nightly-2", want: Workload{"cronjob", "nightly"}, wantState: WorkloadSuperseded},
		{name: "oldest run is superseded", resource: "nightly-1", want: Workload{"cronjob", "nightly"}, wantState: WorkloadSuperseded},
		{name: "job without cronjob", resource: "migrate", want: Workload{"job", "migrate"}, wantState: WorkloadCurrent},
		{name: "run of a cronjob that is deleted", resource: "orphan-1", want: Workload{"cronjob", "removed"}, wantState: WorkloadGone},
		{name: "job missing from the snapshot", resource: "missing", want: Workload{"job", "missing"}, wantState: WorkloadGone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()

			got, state, err := NewWorkloadResolver(c, testNamespace).Resolve(context.Background(), "Job", tt.resource)

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantState, state)
		})
	}
}

func TestWorkloadResolver_Resolve_JobListError(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return assert.AnError
			},
		}).Build()

	_, _, err := NewWorkloadResolver(c, testNamespace).Resolve(context.Background(), "Job", "nightly-1")

	require.ErrorIs(t, err, assert.AnError)
}

func TestWorkloadResolver_Containers(t *testing.T) {
	spec := func(containers, initContainers []string) corev1.PodSpec {
		out := corev1.PodSpec{}
		for _, c := range containers {
			out.Containers = append(out.Containers, corev1.Container{Name: c})
		}

		for _, c := range initContainers {
			out.InitContainers = append(out.InitContainers, corev1.Container{Name: c})
		}

		return out
	}
	objMeta := func(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: testNamespace} }

	objects := []client.Object{
		&appsv1.Deployment{ObjectMeta: objMeta("web"), Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: spec([]string{"app", "proxy"}, []string{"migrate"})},
		}},
		&appsv1.ReplicaSet{ObjectMeta: objMeta("bare"), Spec: appsv1.ReplicaSetSpec{
			Template: corev1.PodTemplateSpec{Spec: spec([]string{"app"}, nil)},
		}},
		&appsv1.StatefulSet{ObjectMeta: objMeta("db"), Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{Spec: spec([]string{"postgres"}, nil)},
		}},
		&appsv1.DaemonSet{ObjectMeta: objMeta("agent"), Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{Spec: spec([]string{"agent"}, nil)},
		}},
		&batchv1.Job{ObjectMeta: objMeta("migrate"), Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: spec([]string{"job"}, nil)},
		}},
		&batchv1.CronJob{ObjectMeta: objMeta("nightly"), Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: spec([]string{"report"}, nil)}},
		}}},
		&corev1.Pod{ObjectMeta: objMeta("debug"), Spec: func() corev1.PodSpec {
			s := spec([]string{"shell"}, nil)
			s.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "tools"}}}

			return s
		}()},
	}

	tests := []struct {
		workload Workload
		want     []string
	}{
		{Workload{"deployment", "web"}, []string{"app", "migrate", "proxy"}},
		{Workload{"replicaset", "bare"}, []string{"app"}},
		{Workload{"statefulset", "db"}, []string{"postgres"}},
		{Workload{"daemonset", "agent"}, []string{"agent"}},
		{Workload{"job", "migrate"}, []string{"job"}},
		{Workload{"cronjob", "nightly"}, []string{"report"}},
		{Workload{"pod", "debug"}, []string{"shell", "tools"}},
	}

	for _, tt := range tests {
		t.Run(tt.workload.String(), func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()

			names, found, err := NewWorkloadResolver(c, testNamespace).Containers(context.Background(), tt.workload)

			require.NoError(t, err)
			assert.True(t, found)
			assert.ElementsMatch(t, tt.want, slices.Collect(maps.Keys(names)))
		})
	}
}

func TestWorkloadResolver_Containers_Absent(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	for _, kind := range []string{"deployment", "replicaset", "statefulset", "daemonset", "job", "cronjob", "pod"} {
		_, found, err := NewWorkloadResolver(c, testNamespace).Containers(context.Background(), Workload{kind, "missing"})

		require.NoError(t, err, kind)
		assert.False(t, found, kind)
	}
}

func TestWorkloadResolver_Containers_UnsupportedKind(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	_, _, err := NewWorkloadResolver(c, testNamespace).Containers(context.Background(), Workload{"replicationcontroller", "x"})

	require.ErrorIs(t, err, ErrUnsupportedKind)
}

// calls counts the Get and List calls of a client by the Go type of the object.
type calls struct {
	gets  map[string]int
	lists map[string]int
	// limits holds the page size of every list call by type.
	limits map[string][]int64
}

func newCalls() *calls {
	return &calls{gets: map[string]int{}, lists: map[string]int{}, limits: map[string][]int64{}}
}

func (c *calls) funcs(pageSize int) interceptor.Funcs {
	return interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			c.gets[fmt.Sprintf("%T", obj)]++

			return cl.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			name := fmt.Sprintf("%T", list)
			c.lists[name]++

			lo := &client.ListOptions{}
			lo.ApplyOptions(opts)
			c.limits[name] = append(c.limits[name], lo.Limit)

			if err := cl.List(ctx, list, opts...); err != nil {
				return err
			}

			if pageSize > 0 {
				page(list, lo.Continue, pageSize)
			}

			return nil
		},
	}
}

// page cuts the items of a list to the page that starts at the continue token, an index, and sets the next token.
func page(list client.ObjectList, token string, size int) {
	items, err := meta.ExtractList(list)
	if err != nil {
		panic(err)
	}

	from, _ := strconv.Atoi(token)
	to := min(from+size, len(items))

	if err = meta.SetList(list, items[from:to]); err != nil {
		panic(err)
	}

	if to < len(items) {
		list.SetContinue(strconv.Itoa(to))
	}
}

func TestWorkloadResolver_Containers_ReadsEachWorkloadOnce(t *testing.T) {
	spy := newCalls()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(
			&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: testNamespace}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: testNamespace}},
		).
		WithInterceptorFuncs(spy.funcs(0)).Build()

	r := NewWorkloadResolver(c, testNamespace)

	for range 3 {
		for _, w := range []Workload{{"statefulset", "db"}, {"statefulset", "other"}, {"pod", "debug"}} {
			_, _, err := r.Containers(context.Background(), w)
			require.NoError(t, err)
		}
	}

	assert.Equal(t, 1, spy.lists["*v1.StatefulSetList"], "a kind is listed once, not read workload by workload")
	assert.Equal(t, map[string]int{"*v1.Pod": 1}, spy.gets, "a Pod is read once; StatefulSets come from the list")
}

func TestWorkloadResolver_StableWorkloads_ListsEachKindOnceInPages(t *testing.T) {
	objMeta := func(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: testNamespace} }
	owned := objMeta("web-abc")
	owned.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-rs", Controller: ptr.To(true),
	}}

	objects := []client.Object{
		newDeployment("web", "1"), newDeployment("api", "1"), newDeployment("worker", "1"),
		newReplicaSet("web-rs", "web", "1", 1), newReplicaSet("bare", "", "", 1), newReplicaSet("bare-2", "", "", 1),
		newJob("nightly-1", "nightly", 0), newJob("migrate", "", 0), newJob("migrate-2", "", 0),
		&appsv1.StatefulSet{ObjectMeta: objMeta("db-0")}, &appsv1.StatefulSet{ObjectMeta: objMeta("db-1")},
		&appsv1.StatefulSet{ObjectMeta: objMeta("db-2")},
		&appsv1.DaemonSet{ObjectMeta: objMeta("agent-0")}, &appsv1.DaemonSet{ObjectMeta: objMeta("agent-1")},
		&batchv1.CronJob{ObjectMeta: objMeta("nightly")}, &batchv1.CronJob{ObjectMeta: objMeta("weekly")},
		&corev1.Pod{ObjectMeta: owned},
		&corev1.Pod{ObjectMeta: objMeta("debug-0")}, &corev1.Pod{ObjectMeta: objMeta("debug-1")},
		&corev1.Pod{ObjectMeta: objMeta("debug-2")},
	}

	for name, tc := range map[string]struct {
		pageSize  int
		wantLists map[string]int
	}{
		"one page": {pageSize: 0, wantLists: map[string]int{
			"*v1.ReplicaSetList": 1, "*v1.DeploymentList": 1, "*v1.JobList": 1,
			"*v1.StatefulSetList": 1, "*v1.DaemonSetList": 1, "*v1.CronJobList": 1, "*v1.PartialObjectMetadataList": 1,
		}},
		"pages of two": {pageSize: 2, wantLists: map[string]int{
			"*v1.ReplicaSetList": 2, "*v1.DeploymentList": 2, "*v1.JobList": 2,
			"*v1.StatefulSetList": 2, "*v1.DaemonSetList": 1, "*v1.CronJobList": 1, "*v1.PartialObjectMetadataList": 2,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			spy := newCalls()
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).
				WithInterceptorFuncs(spy.funcs(tc.pageSize)).Build()
			wantLists := tc.wantLists

			r := NewWorkloadResolver(c, testNamespace)

			// A report of each kind is resolved before the pass asks for every workload.
			for _, ref := range [][2]string{
				{"ReplicaSet", "web-rs"}, {"Job", "migrate"}, {"StatefulSet", "db-1"}, {"DaemonSet", "agent-0"},
				{"CronJob", "nightly"}, {"Pod", "debug-0"},
			} {
				_, state, err := r.Resolve(context.Background(), ref[0], ref[1])
				require.NoError(t, err)
				require.Equal(t, WorkloadCurrent, state, ref)
			}

			workloads, err := r.StableWorkloads(context.Background())
			require.NoError(t, err)

			var got []string
			for _, w := range workloads {
				got = append(got, w.String())
			}

			assert.ElementsMatch(t, []string{
				"deployment/web", "deployment/api", "deployment/worker", "replicaset/bare", "replicaset/bare-2",
				"job/migrate", "job/migrate-2",
				"statefulset/db-0", "statefulset/db-1", "statefulset/db-2", "daemonset/agent-0", "daemonset/agent-1",
				"cronjob/nightly", "cronjob/weekly", "pod/debug-0", "pod/debug-1", "pod/debug-2",
			}, got)

			for kind, want := range wantLists {
				assert.Equal(t, want, spy.lists[kind], kind+" is listed once, in pages")
			}

			for _, kind := range []string{
				"*v1.ReplicaSetList", "*v1.DeploymentList", "*v1.JobList",
				"*v1.StatefulSetList", "*v1.DaemonSetList", "*v1.CronJobList", "*v1.PartialObjectMetadataList",
			} {
				for _, limit := range spy.limits[kind] {
					assert.Equal(t, int64(listPageSize), limit, kind)
				}
			}

			assert.Equal(t, map[string]int{"*v1.Pod": 3}, spy.gets, "one Get per Pod without a controller, none for the others")
		})
	}
}

var listedKinds = []string{
	"*v1.ReplicaSetList", "*v1.DeploymentList", "*v1.JobList",
	"*v1.StatefulSetList", "*v1.DaemonSetList", "*v1.CronJobList", "*v1.PartialObjectMetadataList",
}

func TestWorkloadResolver_StableWorkloads_ErrorOnALaterPage(t *testing.T) {
	objMeta := func(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: testNamespace} }

	objects := []client.Object{
		newDeployment("web", "1"), newDeployment("api", "1"), newReplicaSet("rs-1", "", "", 1), newReplicaSet("rs-2", "", "", 1),
		newJob("job-1", "", 0), newJob("job-2", "", 0),
		&appsv1.StatefulSet{ObjectMeta: objMeta("db-1")}, &appsv1.StatefulSet{ObjectMeta: objMeta("db-2")},
		&appsv1.DaemonSet{ObjectMeta: objMeta("agent-1")}, &appsv1.DaemonSet{ObjectMeta: objMeta("agent-2")},
		&batchv1.CronJob{ObjectMeta: objMeta("cron-1")}, &batchv1.CronJob{ObjectMeta: objMeta("cron-2")},
		&corev1.Pod{ObjectMeta: objMeta("pod-1")}, &corev1.Pod{ObjectMeta: objMeta("pod-2")},
	}

	for _, kind := range listedKinds {
		t.Run(kind, func(t *testing.T) {
			paged := newCalls().funcs(1)

			c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: paged.Get,
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						lo := &client.ListOptions{}
						lo.ApplyOptions(opts)

						if fmt.Sprintf("%T", list) == kind && lo.Continue != "" {
							return k8sErrors.NewResourceExpired("the continue token is too old")
						}

						return paged.List(ctx, cl, list, opts...)
					},
				}).Build()

			workloads, err := NewWorkloadResolver(c, testNamespace).StableWorkloads(context.Background())

			require.Error(t, err)
			assert.True(t, k8sErrors.IsResourceExpired(err))
			assert.Empty(t, workloads, "a list that fails halfway yields no workloads")
		})
	}
}

func TestWorkloadResolver_StableWorkloads_ListError(t *testing.T) {
	for _, kind := range listedKinds {
		t.Run(kind, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t)).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if fmt.Sprintf("%T", list) == kind {
							return assert.AnError
						}

						return cl.List(ctx, list, opts...)
					},
				}).Build()

			_, err := NewWorkloadResolver(c, testNamespace).StableWorkloads(context.Background())

			require.ErrorIs(t, err, assert.AnError)
		})
	}
}
