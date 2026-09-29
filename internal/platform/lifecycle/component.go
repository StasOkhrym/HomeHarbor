// Package lifecycle contains the deliberately small contracts shared by
// executable runtimes. It is not a service locator: each application still
// owns its dependencies and shutdown order explicitly.
package lifecycle

import "context"

// Component is the common contract for a long-running executable component.
// Run must return when ctx is cancelled or when the component cannot continue.
type Component interface {
	Run(context.Context) error
}
