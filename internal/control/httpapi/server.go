package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/network"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

// DeviceService is intentionally defined by the HTTP consumer. Keeping this
// interface narrow lets the devices module evolve without exposing repository
// details or forcing unrelated transports to depend on HTTP-specific behavior.
type DeviceService interface {
	IssueEnrollmentToken(context.Context, devices.Role, time.Duration) (devices.IssuedToken, error)
	Enroll(context.Context, devices.EnrollRequest) (devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	Revoke(context.Context, string) error
}

type Authorizer interface {
	IsAdmin(context.Context, *http.Request) bool
}

// Server composes optional module capabilities at the HTTP boundary. Domain
// services remain unaware of chi and continue to satisfy narrow interfaces.
type Server struct {
	devices      DeviceService
	network      NetworkService
	policy       PolicyService
	authorizer   Authorizer
	logger       *slog.Logger
	coordination http.Handler
	metrics      http.Handler
}

type NetworkService interface {
	Advertise(context.Context, controlnetwork.AdvertisementRequest) (controlnetwork.Advertisement, error)
	Approve(context.Context, string) error
	Reject(context.Context, string) error
	List(context.Context) ([]controlnetwork.Advertisement, error)
}
type ServerOption func(*Server)

func WithNetworkService(service NetworkService) ServerOption {
	return func(server *Server) { server.network = service }
}

type PolicyService interface {
	Replace(context.Context, []policy.Rule) (policy.Snapshot, error)
	Latest(context.Context) (policy.Snapshot, error)
}

func WithPolicyService(service PolicyService) ServerOption {
	return func(server *Server) { server.policy = service }
}
func WithCoordinationHandler(handler http.Handler) ServerOption {
	return func(server *Server) { server.coordination = handler }
}
func WithMetricsHandler(handler http.Handler) ServerOption {
	return func(server *Server) { server.metrics = handler }
}

func NewServer(deviceService DeviceService, authorizer Authorizer, options ...ServerOption) *Server {
	server := &Server{devices: deviceService, authorizer: authorizer, logger: slog.Default()}
	for _, option := range options {
		option(server)
	}
	return server
}
func (s *Server) Handler() http.Handler {
	return recoverMiddleware(NewRouter(s), s.logger)
}
func (s *Server) latestPolicy(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.policy.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load policy")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}
func (s *Server) replacePolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rules []policy.Rule `json:"rules"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	snapshot, err := s.policy.Replace(r.Context(), input.Rules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}
func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	routes := []controlnetwork.Advertisement{}
	if s.network != nil {
		routes, _ = s.network.List(r.Context())
	}
	if err := adminTemplate.Execute(w, map[string]any{"Devices": list, "Routes": routes}); err != nil {
		s.logger.Error("render admin", "error", err)
	}
}
func (s *Server) advertiseRoute(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID              string `json:"id"`
		GatewayDeviceID string `json:"gateway_device_id"`
		Prefix          string `json:"prefix"`
		Resolver        string `json:"resolver"`
		DomainSuffix    string `json:"domain_suffix"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	prefix, err := netip.ParsePrefix(input.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix")
		return
	}
	resolver, err := netip.ParseAddr(input.Resolver)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resolver")
		return
	}
	item, err := s.network.Advertise(r.Context(), controlnetwork.AdvertisementRequest{ID: input.ID, GatewayDeviceID: input.GatewayDeviceID, Prefix: prefix, Resolver: resolver, DomainSuffix: input.DomainSuffix})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}
func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	items, err := s.network.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": items})
}
func (s *Server) approveRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Approve(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) rejectRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Reject(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := s.authorizer != nil && s.authorizer.IsAdmin(r.Context(), r)
		if authorized && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if mutations, ok := s.authorizer.(interface {
				AuthorizeMutation(context.Context, *http.Request) bool
			}); ok {
				authorized = mutations.AuthorizeMutation(r.Context(), r)
			}
		}
		if !authorized {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Role       devices.Role `json:"role"`
		TTLSeconds int64        `json:"ttl_seconds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	token, err := s.devices.IssueEnrollmentToken(r.Context(), input.Role, time.Duration(input.TTLSeconds)*time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, token)
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var input devices.EnrollRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	device, err := s.devices.Enroll(r.Context(), input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, devices.ErrInvalidEnrollmentToken) {
			status = http.StatusUnauthorized
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, device)
}
func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": list})
}
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.devices.Revoke(r.Context(), r.PathValue("id")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, devices.ErrDeviceNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func recoverMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				logger.Error("HTTP panic", "error", value)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Go Tunnels</title><script src="https://unpkg.com/htmx.org@2.0.7"></script><style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;background:#0b1020;color:#e8edf7}table{width:100%;border-collapse:collapse;background:#141b2d;margin-bottom:2rem}th,td{text-align:left;padding:.8rem;border-bottom:1px solid #28324a}.active,.approved{color:#5ee6a8}.revoked,.rejected{color:#ff7c8a}.pending{color:#ffd166}code{color:#9dc1ff}</style></head><body><h1>Go Tunnels</h1><p>Homelab control plane</p><h2>Devices</h2><table><thead><tr><th>Name</th><th>Role</th><th>Status</th><th>Device ID</th></tr></thead><tbody>{{range .Devices}}<tr><td>{{.Name}}</td><td>{{.Role}}</td><td class="{{.Status}}">{{.Status}}</td><td><code>{{.ID}}</code></td></tr>{{else}}<tr><td colspan="4">No enrolled devices.</td></tr>{{end}}</tbody></table><h2>Routes and split DNS</h2><table><thead><tr><th>Prefix</th><th>Resolver</th><th>Domain</th><th>Status</th></tr></thead><tbody>{{range .Routes}}<tr><td><code>{{.Prefix}}</code></td><td><code>{{.Resolver}}</code></td><td>{{.DomainSuffix}}</td><td class="{{.Status}}">{{.Status}}</td></tr>{{else}}<tr><td colspan="4">No advertised routes.</td></tr>{{end}}</tbody></table></body></html>`))
