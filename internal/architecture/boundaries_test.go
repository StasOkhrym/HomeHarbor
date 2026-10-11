package architecture

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/routes"
	memoryroutes "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
)

// The import graph is the module boundary: a domain must not acquire storage
// or HTTP dependencies when another adapter is added to the composition root.
func TestDomainModulesDoNotImportAdapters(t *testing.T) {
	modules := []string{
		"identity",
		"devices",
		"routes",
		"policy",
		"services",
		"profiles",
		"invites",
		"snapshots",
		"audit",
	}
	for _, module := range modules {
		t.Run(module, func(t *testing.T) {
			checkDomainImports(
				t,
				filepath.Join("..", ".."),
				"internal/control/"+module,
				make(map[string]bool),
			)
		})
	}
}

// Browser and JSON transports are composed by app/control. Keeping their
// imports separate prevents a presentation change from expanding the API
// adapter's dependency graph or forcing browser handlers back into it.
func TestBrowserAndJSONAdaptersAreSiblings(t *testing.T) {
	const module = "github.com/StasOkhrym/homeharbor/internal/"
	for _, item := range []struct {
		folder    string
		forbidden string
	}{
		{"control/httpapi", module + "web/admin"},
		{"control/httpapi", module + "web/auth"},
		{"web/admin", module + "control/httpapi"},
		{"web/auth", module + "control/httpapi"},
	} {
		t.Run(item.folder+"-to-"+item.forbidden, func(t *testing.T) {
			folder := filepath.Join("..", "..", "internal", item.folder)

			entries, err := os.ReadDir(folder)
			if err != nil {
				t.Fatal(err)
			}

			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
					strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}

				path := filepath.Join(folder, entry.Name())

				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if err != nil {
					t.Fatal(err)
				}

				for _, spec := range file.Imports {
					importPath, err := strconv.Unquote(spec.Path.Value)
					if err != nil {
						t.Fatal(err)
					}

					if importPath == item.forbidden {
						t.Errorf("%s imports sibling adapter %s", path, importPath)
					}
				}
			}
		})
	}
}

// Follow local imports too: a domain helper must not hide an adapter dependency.
func checkDomainImports(t *testing.T, repositoryRoot, packagePath string, visited map[string]bool) {
	t.Helper()
	if visited[packagePath] {
		return
	}

	visited[packagePath] = true
	root := filepath.Join(repositoryRoot, packagePath)

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		path := filepath.Join(root, entry.Name())

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}

		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}

			if forbiddenDomainImport(importPath) {
				t.Errorf("domain %s imports adapter %s", path, importPath)

				continue
			}

			if strings.HasPrefix(importPath, "github.com/StasOkhrym/homeharbor/internal/") {
				checkDomainImports(
					t,
					repositoryRoot,
					strings.TrimPrefix(importPath, "github.com/StasOkhrym/homeharbor/"),
					visited,
				)
			}
		}
	}
}

func forbiddenDomainImport(path string) bool {
	return path == "net/http" || strings.HasPrefix(path, "net/http/") ||
		strings.HasPrefix(path, "github.com/jackc/pgx/") ||
		strings.HasPrefix(path, "github.com/redis/go-redis/") ||
		strings.HasPrefix(path, "github.com/go-chi/chi/") ||
		strings.Contains(path, "/storage") || strings.Contains(path, "/httpapi") ||
		strings.HasSuffix(path, "/control/transactions")
}

// Test helpers may depend on domains; runtime packages may not depend on test helpers.
func TestProductionPackagesDoNotImportTestutil(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, top := range []string{"cmd", "internal", "migrations"} {
		err := filepath.WalkDir(
			filepath.Join(root, top),
			func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					if path == filepath.Join(root, "internal", "testutil") {
						return filepath.SkipDir
					}

					return nil
				}
				if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}

				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if err != nil {
					return err
				}

				for _, spec := range file.Imports {
					importPath, err := strconv.Unquote(spec.Path.Value)
					if err != nil {
						return err
					}

					if strings.HasPrefix(
						importPath,
						"github.com/StasOkhrym/homeharbor/internal/testutil",
					) {
						t.Errorf("production file %s imports %s", path, importPath)
					}
				}

				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDomainBoundaryRejectsNeutralStorageAdapters(t *testing.T) {
	for _, path := range []string{
		"github.com/StasOkhrym/homeharbor/internal/control/devices/storage",
		"github.com/StasOkhrym/homeharbor/internal/control/transactions",
	} {
		if !forbiddenDomainImport(path) {
			t.Errorf("domain boundary permits durable adapter %s", path)
		}
	}
}

func TestControlModulesDoNotUseDotImports(t *testing.T) {
	for _, module := range []string{"identity", "devices", "routes", "policy", "services", "profiles", "invites", "snapshots", "audit"} {
		err := filepath.WalkDir(
			filepath.Join("..", "control", module),
			func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() || !strings.HasSuffix(path, ".go") {
					return nil
				}
				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if err != nil {
					return err
				}
				for _, spec := range file.Imports {
					if spec.Name != nil && spec.Name.Name == "." {
						t.Errorf("%s uses a dot import of %s", path, spec.Path.Value)
					}
				}
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// These are public responses from the moved modules, not persistence payloads.
// Keep literal expectations so renamed packages cannot silently alter the wire.
func TestMovedDomainWireJSON(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	service := routes.NewService(memoryroutes.NewRepository(), func() time.Time { return now })

	advertisement, err := service.Advertise(context.Background(), routes.AdvertisementRequest{
		ID: "route-1", GatewayDeviceID: "gateway-1", Prefix: netip.MustParsePrefix("10.20.1.0/16"),
		Resolver: netip.MustParseAddr("10.20.0.53"), DomainSuffix: " HOME.ARPA. ",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		value any
		want  string
	}{
		{"advertisement", advertisement, `{"id":"route-1","gateway_device_id":"gateway-1","prefix":"10.20.0.0/16","resolver":"10.20.0.53","domain_suffix":"home.arpa","status":"pending","created_at":"2026-09-29T12:00:00Z"}`},
		{"audit", audit.Event{OccurredAt: now, ActorType: "device", ActorID: "device-1", Action: "device.enrolled", TargetType: "device", TargetID: "device-1", Metadata: map[string]any{"success": true}}, `{"occurred_at":"2026-09-29T12:00:00Z","actor_type":"device","actor_id":"device-1","action":"device.enrolled","target_type":"device","target_id":"device-1","metadata":{"success":true}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}

			if string(got) != test.want {
				t.Fatalf("wire JSON = %s, want %s", got, test.want)
			}
		})
	}
}
