package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	webadmin "github.com/StasOkhrym/homeharbor/internal/web/admin"
)

func parseBrowserForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// FormValue silently discards ParseForm errors. Reject malformed
			// bodies before authentication or field validation uses those values.
			if err := r.ParseForm(); err != nil {
				writeError(w, http.StatusBadRequest, "invalid form body")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func csrfFormToken(request *http.Request) string {
	cookie, err := request.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func newBrowserID() (string, error) {
	var value [16]byte

	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(value[:]), nil
}

func browserFormID(r *http.Request) (string, error) {
	if value := strings.TrimSpace(r.FormValue("id")); value != "" {
		if len(value) > 128 {
			return "", errBrowserID
		}

		for _, char := range value {
			letter := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
			digit := char >= '0' && char <= '9'
			if !letter && !digit && char != '-' && char != '_' {
				return "", errBrowserID
			}
		}

		return value, nil
	}

	return newBrowserID()
}

// Browser IDs enter URL paths. The override is bounded and path-safe without
// changing the JSON API's existing identifier contract.
var errBrowserID = errors.New("use at most 128 letters, numbers, hyphens or underscores for the ID")

func browserIDError(err error) (int, string) {
	if errors.Is(err, errBrowserID) {
		return http.StatusUnprocessableEntity, errBrowserID.Error()
	}

	return http.StatusServiceUnavailable, "A record ID could not be generated. Try again."
}

// Only non-secret form fields survive a validation error. Copying all PostForm
// values would retain CSRF/confirmation tokens or future secret inputs.
func safeFormValues(r *http.Request) url.Values {
	_ = r.ParseForm()
	values := url.Values{}
	for _, key := range []string{
		"id", "name", "kind", "url", "native_url", "health_url", "description",
		"gateway_device_id", "prefix", "resolver", "domain_suffix", "device_ids", "service_ids",
		"role", "ttl_seconds", "rules", "rule_id", "source_device_id", "destination", "protocol",
		"port_from", "port_to", "editor",
	} {
		if submitted, ok := r.PostForm[key]; ok {
			values[key] = append([]string(nil), submitted...)
		}
	}

	// URLs are ordinary catalog fields, but rejected userinfo may contain a
	// password. Keep the address for correction, never echo that credential.
	for _, key := range []string{"url", "native_url", "health_url"} {
		for index, raw := range values[key] {
			parsed, err := url.Parse(raw)
			if err != nil {
				// An invalid escape can conceal userinfo from the parser. There is
				// no safe address to retain when parsing fails.
				values[key][index] = ""
			} else if parsed.User != nil {
				parsed.User = nil
				values[key][index] = parsed.String()
			}
		}
	}

	return values
}

func (s *Server) adminFormError(
	w http.ResponseWriter,
	r *http.Request,
	page string,
	status int,
	field, message string,
) {
	model, _ := s.loadAdminPage(r, page)
	for key, values := range safeFormValues(r) {
		model.Values[key] = values
	}
	if page == "access" && r.FormValue("editor") == "structured" {
		model.PolicyRows = webadmin.SubmittedPolicyRows(model.Values)
	}
	model.FieldErrors[field] = message
	model.Error = "Your changes were not saved. " + message
	s.renderAdmin(w, status, model)
}

func formSelections(r *http.Request, key string) []string {
	_ = r.ParseForm()
	// Checkbox values are opaque domain identifiers, not legacy CSV input.
	return append([]string(nil), r.PostForm[key]...)
}

func redirectAdmin(w http.ResponseWriter, r *http.Request, notice string) {
	path := "/admin/"
	// A closed set of destinations prevents open redirects and preserves the
	// old root redirect when an older form does not provide return_to.
	switch r.FormValue("return_to") {
	case "services", "access", "network", "devices", "invites":
		path += r.FormValue("return_to")
	}

	http.Redirect(w, r, path+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
