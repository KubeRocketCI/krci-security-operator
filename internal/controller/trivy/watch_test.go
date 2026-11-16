package trivy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newQueue() queue {
	return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
}

func drain(t *testing.T, q queue) []string {
	t.Helper()

	var out []string

	for q.Len() > 0 {
		item, _ := q.Get()
		out = append(out, item.Name)

		q.Done(item)
	}

	return out
}

func TestEnqueueNamespaceOf(t *testing.T) {
	report := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: stageNS}}

	assert.Equal(t, []reconcile.Request{namespaceRequest(stageNS)}, enqueueNamespaceOf(context.Background(), report))
	assert.Empty(t, enqueueNamespaceOf(context.Background(), &corev1.Namespace{}), "a cluster-scoped object has no namespace")
}

func TestNamespaceRequestKeyIsTheNamespaceName(t *testing.T) {
	assert.Equal(t, client.ObjectKey{Name: stageNS}, namespaceRequest(stageNS).NamespacedName)
}

func TestStageHandler(t *testing.T) {
	h := stageHandler()
	moved := newStage("demo-dev", "dev", "krci-demo-new", inClusterName)

	t.Run("create enqueues the namespace of the Stage", func(t *testing.T) {
		q := newQueue()
		h.Create(context.Background(), event.CreateEvent{Object: demoStage()}, q)

		assert.Equal(t, []string{stageNS}, drain(t, q))
	})

	t.Run("update enqueues the new and the old namespace", func(t *testing.T) {
		q := newQueue()
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: demoStage(), ObjectNew: moved}, q)

		assert.ElementsMatch(t, []string{stageNS, "krci-demo-new"}, drain(t, q))
	})

	t.Run("update inside one namespace enqueues it once", func(t *testing.T) {
		q := newQueue()
		h.Update(context.Background(), event.UpdateEvent{ObjectOld: demoStage(), ObjectNew: demoStage()}, q)

		assert.Equal(t, []string{stageNS}, drain(t, q))
	})

	t.Run("delete enqueues the namespace of the Stage", func(t *testing.T) {
		q := newQueue()
		h.Delete(context.Background(), event.DeleteEvent{Object: demoStage()}, q)

		assert.Equal(t, []string{stageNS}, drain(t, q))
	})

	t.Run("a Stage without a namespace enqueues nothing", func(t *testing.T) {
		q := newQueue()
		h.Create(context.Background(), event.CreateEvent{Object: newStage("x", "dev", "", inClusterName)}, q)
		h.Generic(context.Background(), event.GenericEvent{Object: &corev1.Namespace{}}, q)

		assert.Empty(t, drain(t, q))
	})
}

func TestControllerOptions(t *testing.T) {
	cfg := baseConfig()
	cfg.Concurrency = 3

	opts := controllerOptions(cfg)

	assert.Equal(t, 3, opts.MaxConcurrentReconciles)
	require.NotNil(t, opts.RateLimiter)

	req := namespaceRequest(stageNS)

	assert.Equal(t, 30*time.Second, opts.RateLimiter.When(req))
	assert.Equal(t, time.Minute, opts.RateLimiter.When(req))

	for range 20 {
		opts.RateLimiter.When(req)
	}

	assert.Equal(t, 10*time.Minute, opts.RateLimiter.When(req))
}

func TestParseStage(t *testing.T) {
	s := parseStage(demoStage())

	assert.Equal(t, stageRef{
		namespace: tenantNS, name: "demo-dev", cdPipeline: "demo", stage: "dev",
		clusterName: inClusterName, targetNamespace: stageNS,
	}, s)
	assert.Equal(t, "krci/demo-dev", s.String())
	assert.Empty(t, s.invalidName())
	assert.Equal(t, "spec.name", parseStage(newStage("x", "Dev", stageNS, inClusterName)).invalidName())
	assert.Equal(t, "spec.namespace", parseStage(newStage("x", "dev", "a.b", inClusterName)).invalidName())
	assert.Empty(t, parseStage(&unstructured.Unstructured{}).targetNamespace)
}

func TestNamespacePredicate(t *testing.T) {
	p := namespacePredicate()
	ns := tenantNamespace(stageNS)

	relabeled := ns.DeepCopy()
	relabeled.Labels = nil

	terminating := ns.DeepCopy()
	terminating.DeletionTimestamp = &metav1.Time{Time: scanDate}

	assert.True(t, p.Create(event.CreateEvent{Object: ns}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: ns}))
	assert.True(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: relabeled}), "a label change")
	assert.True(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: terminating}), "the start of the termination")
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: ns.DeepCopy()}), "no relevant change")
}
