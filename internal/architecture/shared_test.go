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
	for _, pkg := range []string{"internal/node", "internal/app/node", "internal/companion", "cmd/admin", "cmd/client", "cmd/agent"} {
		checkSharedImports(t, pkg, map[string]bool{}, false)
	}
}

func checkSharedImports(t *testing.T, pkg string, seen map[string]bool, pure bool) {
	t.Helper()
	for _, violation := range sharedImportViolations(t, "../..", pkg, seen, pure) {
		t.Error(violation)
	}
}

func sharedImportViolations(
	t *testing.T,
	repositoryRoot, pkg string,
	seen map[string]bool,
	pure bool,
) []string {
	t.Helper()
	if seen[pkg] {
		return nil
	}

	seen[pkg] = true
	var violations []string
	root := filepath.Join(repositoryRoot, pkg)

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
				violations = append(
					violations,
					pkg+"/"+entry.Name()+" imports forbidden dependency "+imp,
				)
				continue
			}

			if strings.HasPrefix(imp, "github.com/StasOkhrym/homeharbor/internal/") {
				violations = append(violations, sharedImportViolations(
					t, repositoryRoot,
					strings.TrimPrefix(imp, "github.com/StasOkhrym/homeharbor/"),
					seen,
					pure,
				)...)
			}
		}
	}

	return violations
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

func TestSharedImportTraversalRejectsTransitiveControlDependency(t *testing.T) {
	root := t.TempDir()
	for pkg, source := range map[string]string{
		"internal/app/node": `package node; import _ "github.com/StasOkhrym/homeharbor/internal/helper"`,
		"internal/helper":   `package helper; import _ "github.com/StasOkhrym/homeharbor/internal/control/devices"`,
	} {
		dir := filepath.Join(root, pkg)

		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(
			filepath.Join(dir, "production.go"),
			[]byte(source),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	violations := sharedImportViolations(t, root, "internal/app/node", map[string]bool{}, false)
	want := "internal/helper/production.go imports forbidden dependency github.com/StasOkhrym/homeharbor/internal/control/devices"

	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("violations = %v, want %q", violations, want)
	}
}
