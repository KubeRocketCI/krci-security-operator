package trivy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MaxListRestarts is how often a listing starts again after its continue token expired.
const MaxListRestarts = 3

// ErrKindNotServed means the cluster does not serve the kind of the objects that are listed, also when it stops
// serving it while the pages are read.
var ErrKindNotServed = errors.New("kind is not served")

// Listing is a paged list of the objects of one namespace.
type Listing[L client.ObjectList] struct {
	Reader    client.Reader
	Namespace string
	// What names the listed objects in errors.
	What     string
	PageSize int64
	// KindMayBeUnserved maps a kind the cluster does not serve to ErrKindNotServed. Default false: the listing fails.
	KindMayBeUnserved bool
	NewList           func() L
	// Each handles one page. Its error ends the listing and is returned as it is.
	Each func(L) error
	// Restart is called before the listing starts again. It drops what Each collected from the earlier pages.
	Restart func()
}

// ListPages reads the pages of the listing one after the other and hands each to Each.
// A continue token that expired (HTTP 410) starts the listing again, at most MaxListRestarts times; the listing that
// still fails after the last restart fails. A kind the cluster does not serve gives ErrKindNotServed when
// KindMayBeUnserved is set.
func ListPages[L client.ObjectList](ctx context.Context, l Listing[L]) error {
	base := []client.ListOption{client.InNamespace(l.Namespace), client.Limit(l.PageSize)}
	opts := base
	restarts := 0

	for {
		list := l.NewList()

		err := l.Reader.List(ctx, list, opts...)

		switch {
		case err == nil:
			// The page is handled below.
		case l.KindMayBeUnserved && (meta.IsNoMatchError(err) || k8sErrors.IsNotFound(err)):
			return fmt.Errorf("failed to list %s: %w: %w", l.What, ErrKindNotServed, err)
		case continueExpired(err) && restarts < MaxListRestarts:
			restarts++
			opts = base

			l.Restart()

			continue
		case continueExpired(err):
			return fmt.Errorf("failed to list %s: continue token expired after %d restarts: %w", l.What, restarts, err)
		default:
			return fmt.Errorf("failed to list %s: %w", l.What, err)
		}

		if err = l.Each(list); err != nil {
			return err
		}

		next := list.GetContinue()
		if next == "" {
			return nil
		}

		opts = append(slices.Clone(base), client.Continue(next))
	}
}

// continueExpired reports whether a list failed because its continue token is too old (HTTP 410).
func continueExpired(err error) bool {
	return k8sErrors.IsResourceExpired(err) || k8sErrors.IsGone(err)
}
