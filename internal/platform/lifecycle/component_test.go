package lifecycle

import (
	"context"
	"testing"
)

func TestFuncImplementsComponent(t *testing.T) {
	var component Component = Func(func(context.Context) error { return nil })

	if err := component.Run(context.Background()); err != nil {
		t.Fatalf("component.Run() error=%v", err)
	}
}
