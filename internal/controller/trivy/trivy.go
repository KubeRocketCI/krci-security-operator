// Package trivy is the module that imports Trivy Operator reports into DefectDojo.
package trivy

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/KubeRocketCI/krci-security-operator/pkg/defectdojo"
	"github.com/KubeRocketCI/krci-security-operator/pkg/trivy"
)

const (
	controllerName = "trivy"

	// retryBaseDelay and retryMaxDelay bound the backoff of a failed namespace. A failed reimport is not retried
	// within seconds: DefectDojo may still be processing it.
	retryBaseDelay = 30 * time.Second
	retryMaxDelay  = 10 * time.Minute
)

func controllerOptions(cfg Config) controller.Options {
	return controller.Options{
		MaxConcurrentReconciles: cfg.Concurrency,
		RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
			retryBaseDelay, retryMaxDelay),
	}
}

// SetupWithManager registers the module with the manager: the namespace controller and the sweeper.
//
// The controller watches the metadata of the reports only. The full reports, the workloads and the credentials
// Secret are read through the API reader and never cached.
func SetupWithManager(mgr ctrl.Manager, cfg Config) error {
	r := NewReconciler(mgr.GetCache(), mgr.GetAPIReader(), cfg, NewConnector(defectdojo.New()))

	b := ctrl.NewControllerManagedBy(mgr).
		Named(controllerName).
		For(&corev1.Namespace{}, builder.WithPredicates(namespacePredicate())).
		WithOptions(controllerOptions(cfg))

	log := mgr.GetLogger().WithName(controllerName)

	for _, kind := range cfg.ReportKinds {
		gvk := trivy.ReportGVK(kind)

		served, err := isServed(mgr, gvk)
		if err != nil {
			return err
		}

		if !served {
			log.Info("Skipped the watch of a report kind that the cluster does not serve", "kind", kind)

			continue
		}

		report := &metav1.PartialObjectMetadata{}
		report.SetGroupVersionKind(gvk)

		b = b.Watches(report, handler.EnqueueRequestsFromMapFunc(enqueueNamespaceOf),
			builder.OnlyMetadata, builder.WithPredicates(reportPredicate()))
	}

	b = b.WatchesRawSource(source.Channel(r.wake, handler.EnqueueRequestsFromMapFunc(enqueueNamed)))

	if err := b.Complete(r); err != nil {
		return fmt.Errorf("failed to build Trivy controller: %w", err)
	}

	if err := mgr.Add(manager.RunnableFunc(r.runSweeper)); err != nil {
		return fmt.Errorf("failed to add Trivy sweeper: %w", err)
	}

	log.Info("Registered Trivy module", "clusterName", cfg.ClusterName, "productType", cfg.ProductType)

	return nil
}

// isServed reports whether the cluster serves the kind.
func isServed(mgr ctrl.Manager, gvk schema.GroupVersionKind) (bool, error) {
	if _, err := mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version); err != nil {
		if meta.IsNoMatchError(err) {
			return false, nil
		}

		return false, fmt.Errorf("failed to look up %s: %w", gvk, err)
	}

	return true, nil
}

// reportPredicate drops the updates that change no resourceVersion, which are informer resyncs.
func reportPredicate() predicate.Predicate { return predicate.ResourceVersionChangedPredicate{} }

// namespacePredicate passes creations, deletions and the start of the termination.
func namespacePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp())
		},
	}
}
