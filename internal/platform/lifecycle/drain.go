package lifecycle

import (
	"context"
	"sync"
)

type drainObserverKey struct{}

type drainObserver struct {
	once   sync.Once
	parent *drainObserver
	notify func()
}

// WithDrainObserver connects unexpected essential exits to the caller's process
// policy without giving application code an OS exit dependency. Notifications
// occur once across nested supervisors. Additional observers retain the parent
// policy, which runs first; callbacks must return promptly and never close stores.
func WithDrainObserver(ctx context.Context, notify func()) context.Context {
	if notify == nil {
		return ctx
	}

	parent, _ := ctx.Value(drainObserverKey{}).(*drainObserver)

	return context.WithValue(
		ctx,
		drainObserverKey{},
		&drainObserver{parent: parent, notify: notify},
	)
}

func notifyDrain(ctx context.Context) {
	if observer, ok := ctx.Value(drainObserverKey{}).(*drainObserver); ok {
		observer.observe()
	}
}

func (o *drainObserver) observe() {
	o.once.Do(func() {
		if o.parent != nil {
			o.parent.observe()
		}

		o.notify()
	})
}
