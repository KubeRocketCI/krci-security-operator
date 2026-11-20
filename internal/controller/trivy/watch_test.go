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
	p := namespacePredicate(nil)
	ns := namespaceObject(appNS, map[string]string{"team": "a"})

	relabeled := ns.DeepCopy()
	relabeled.Labels = nil

	terminating := ns.DeepCopy()
	terminating.DeletionTimestamp = &metav1.Time{Time: scanDate}

	assert.True(t, p.Create(event.CreateEvent{Object: ns}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: ns}))
	assert.True(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: terminating}), "the start of the termination")
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: relabeled}), "no label key is listed")
	assert.False(t, p.Update(event.UpdateEvent{ObjectOld: ns, ObjectNew: ns.DeepCopy()}), "no relevant change")
}

func TestNamespacePredicate_ListedLabels(t *testing.T) {
	p := namespacePredicate([]string{"example.com/tenant", "env"})

	base := map[string]string{"example.com/tenant": "krci", "env": "dev", "owner": "a"}

	tests := []struct {
		name        string
		from, to    map[string]string
		terminating bool
		want        bool
	}{
		{name: "a listed label gets another value", from: base, want: true,
			to: map[string]string{"example.com/tenant": "other", "env": "dev", "owner": "a"}},
		{name: "a listed label is removed", from: base, want: true,
			to: map[string]string{"example.com/tenant": "krci", "owner": "a"}},
		{name: "a label that is not listed changes", from: base,
			to: map[string]string{"example.com/tenant": "krci", "env": "dev", "owner": "b"}},
		{name: "a label that is not listed is added", from: base,
			to: map[string]string{"example.com/tenant": "krci", "env": "dev", "owner": "a", "extra": "1"}},
		{name: "a label that is not listed is removed", from: base,
			to: map[string]string{"example.com/tenant": "krci", "env": "dev"}},
		{name: "no label changes", from: base, to: base},
		{name: "all labels are removed", from: base, want: true},
		{name: "a listed label is added to a namespace without labels", to: map[string]string{"env": "dev"}, want: true},
		{name: "a listed label with an empty value is removed", from: map[string]string{"env": ""}},
		{name: "a listed label with an empty value is added", to: map[string]string{"env": ""}},
		{name: "the case of the value of a listed label changes", from: map[string]string{"env": "Dev"},
			to: map[string]string{"env": "dev"}},
		{name: "a listed label with an empty value gets a value", from: map[string]string{"env": ""},
			to: map[string]string{"env": "dev"}, want: true},
		{name: "a namespace without labels", from: nil, to: nil},
		{name: "the start of the termination", from: base, to: base, terminating: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated := namespaceObject(appNS, tt.to)
			if tt.terminating {
				updated.DeletionTimestamp = &metav1.Time{Time: scanDate}
			}

			assert.Equal(t, tt.want, p.Update(event.UpdateEvent{ObjectOld: namespaceObject(appNS, tt.from), ObjectNew: updated}))
		})
	}
}
