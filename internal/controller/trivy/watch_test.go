package trivy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestEnqueueNamespaceOf(t *testing.T) {
	report := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: appNS}}

	assert.Equal(t, []reconcile.Request{namespaceRequest(appNS)}, enqueueNamespaceOf(context.Background(), report))
	assert.Empty(t, enqueueNamespaceOf(context.Background(), &corev1.Namespace{}), "a cluster-scoped object has no namespace")
}

func TestNamespaceRequestKeyIsTheNamespaceName(t *testing.T) {
	assert.Equal(t, client.ObjectKey{Name: appNS}, namespaceRequest(appNS).NamespacedName)
}

func TestControllerOptions(t *testing.T) {
	cfg := baseConfig()
	cfg.Concurrency = 3

	opts := controllerOptions(cfg)

	assert.Equal(t, 3, opts.MaxConcurrentReconciles)
	require.NotNil(t, opts.RateLimiter)

	req := namespaceRequest(appNS)

	assert.Equal(t, 30*time.Second, opts.RateLimiter.When(req))
	assert.Equal(t, time.Minute, opts.RateLimiter.When(req))

	for range 20 {
		opts.RateLimiter.When(req)
	}

	assert.Equal(t, 10*time.Minute, opts.RateLimiter.When(req))
}

func TestNamespacePredicate(t *testing.T) {
	p := namespacePredicate()
	ns := namespaceObject(appNS, map[string]string{"team": "a"})

	relabeled := ns.DeepCopy()
	relabeled.Labels = nil

	terminating := ns.DeepCopy()
	terminating.DeletionTimestamp = &metav1.Time{Time: scanDate}

	assert.True(t, p.Create(event.CreateEvent{Object: ns}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: ns}))
	assert.True(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: terminating}), "the start of the termination")
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: relabeled}), "a label change decides nothing")
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: ns.DeepCopy()}), "no relevant change")
}
