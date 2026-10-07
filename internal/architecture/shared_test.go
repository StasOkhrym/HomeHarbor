package architecture

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNodeAndCompanionHaveNoControlImports(t *testing.T) {
	for _, pkg := range []string{"internal/node", "internal/companion"} {
		checkSharedImports(t, pkg, map[string]bool{}, false)
	}
}

func checkSharedImports(t *testing.T, pkg string, seen map[string]bool, pure bool) {
	t.Helper()
	if seen[pkg] {
		return
	}
	seen[pkg] = true
	root := filepath.Join("../..", pkg)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(
			token.NewFileSet(),
			filepath.Join(root, entry.Name()),
			nil,
			parser.ImportsOnly,
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(imp, "/internal/control/") ||
				strings.Contains(imp, "/internal/app/control") ||
				(pure && (forbiddenDomainImport(imp) || forbiddenSharedRoleImport(imp))) {
				t.Errorf("%s/%s imports forbidden dependency %s", pkg, entry.Name(), imp)
				continue
			}
			if strings.HasPrefix(imp, "github.com/StasOkhrym/homeharbor/internal/") {
				checkSharedImports(
					t,
					strings.TrimPrefix(imp, "github.com/StasOkhrym/homeharbor/"),
					seen,
					pure,
				)
			}
		}
	}
}

func TestSharedPackagesArePure(t *testing.T) {
	for _, pkg := range []string{"internal/acl", "internal/protocol"} {
		checkSharedImports(t, pkg, map[string]bool{}, true)
	}
}

func forbiddenSharedRoleImport(imp string) bool {
	for _, role := range []string{"app", "node", "agent", "companion", "relay", "cli", "platform", "testutil"} {
		prefix := "github.com/StasOkhrym/homeharbor/internal/" + role
		if imp == prefix || strings.HasPrefix(imp, prefix+"/") {
			return true
		}
	}

	return false
}

func TestProtocolDoesNotOwnMutablePathSelection(t *testing.T) {
	entries, err := os.ReadDir("../protocol")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		file, err := parser.ParseFile(
			token.NewFileSet(),
			filepath.Join("../protocol", entry.Name()),
			nil,
			0,
		)
		if err != nil {
			t.Fatal(err)
		}

		if file.Scope.Lookup("PathSelector") != nil || file.Scope.Lookup("NewPathSelector") != nil {
			t.Errorf("protocol/%s owns mutable path selection", entry.Name())
		}
	}
}
