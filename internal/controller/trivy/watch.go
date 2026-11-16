package trivy

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type queue = workqueue.TypedRateLimitingInterface[reconcile.Request]

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

// stageHandler enqueues the namespace a Stage points at, and for an update the previous one too.
func stageHandler() handler.TypedEventHandler[client.Object, reconcile.Request] {
	add := func(q queue, obj client.Object) {
		if ns := stageNamespace(obj); ns != "" {
			q.Add(namespaceRequest(ns))
		}
	}

	return handler.TypedFuncs[client.Object, reconcile.Request]{
		CreateFunc: func(_ context.Context, e event.TypedCreateEvent[client.Object], q queue) {
			add(q, e.Object)
		},
		UpdateFunc: func(_ context.Context, e event.TypedUpdateEvent[client.Object], q queue) {
			add(q, e.ObjectNew)
			add(q, e.ObjectOld)
		},
		DeleteFunc: func(_ context.Context, e event.TypedDeleteEvent[client.Object], q queue) {
			add(q, e.Object)
		},
		GenericFunc: func(_ context.Context, e event.TypedGenericEvent[client.Object], q queue) {
			add(q, e.Object)
		},
	}
}

// stageNamespace returns spec.namespace of a Stage.
func stageNamespace(obj client.Object) string {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return ""
	}

	return parseStage(u).targetNamespace
}
