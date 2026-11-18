package trivy

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// namespaceRequest is the reconcile request of a namespace: its name is the key.
func namespaceRequest(namespace string) reconcile.Request {
	return reconcile.Request{NamespacedName: client.ObjectKey{Name: namespace}}
}

// enqueueNamespaceOf maps an object, a report for example, to the namespace it lives in.
func enqueueNamespaceOf(_ context.Context, obj client.Object) []reconcile.Request {
	if obj.GetNamespace() == "" {
		return nil
	}

	return []reconcile.Request{namespaceRequest(obj.GetNamespace())}
}

// enqueueNamed maps a Namespace object, as the sweeper sends it, to its own name.
func enqueueNamed(_ context.Context, obj client.Object) []reconcile.Request {
	return []reconcile.Request{namespaceRequest(obj.GetName())}
}
