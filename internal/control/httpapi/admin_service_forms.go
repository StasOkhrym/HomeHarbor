package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
)

func (s *Server) createServiceForm(w http.ResponseWriter, r *http.Request) {
	if s.services == nil {
		s.adminFormError(
			w,
			r,
			"services",
			http.StatusServiceUnavailable,
			"form",
			"Services are not configured.",
		)
		return
	}
	name, kind := strings.TrimSpace(r.FormValue("name")), r.FormValue("kind")
	if name == "" {
		s.adminFormError(w, r, "services", http.StatusBadRequest, "name", "Enter a service name.")
		return
	}
	if kind != "web" && kind != "native" {
		s.adminFormError(w, r, "services", http.StatusBadRequest, "kind", "Choose Web or Native.")
		return
	}
	for _, key := range []string{"url", "health_url", "native_url"} {
		value := strings.TrimSpace(r.FormValue(key))
		if value == "" && key != "url" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
			parsed.Fragment != "" ||
			(key != "native_url" && strings.ToLower(parsed.Scheme) != "https") ||
			(key == "native_url" && unsafeAppScheme(parsed.Scheme)) {
			s.adminFormError(
				w,
				r,
				"services",
				http.StatusBadRequest,
				key,
				"Enter a valid URL. Web and health URLs must use HTTPS.",
			)
			return
		}
	}
	id, err := browserFormID(r)
	if err != nil {
		status, message := browserIDError(err)
		s.adminFormError(w, r, "services", status, "id", message)
		return
	}
	item := controlservices.Service{
		ID:          id,
		Name:        name,
		Kind:        controlservices.Kind(kind),
		URL:         strings.TrimSpace(r.FormValue("url")),
		NativeURL:   strings.TrimSpace(r.FormValue("native_url")),
		HealthURL:   strings.TrimSpace(r.FormValue("health_url")),
		Description: strings.TrimSpace(r.FormValue("description")),
	}
	if _, err = s.services.Create(r.Context(), item); err != nil {
		status, field, message := http.StatusServiceUnavailable, "form", "The service could not be saved. Try again shortly."
		if errors.Is(err, controlservices.ErrDuplicateID) {
			status, field, message = http.StatusConflict, "id", "This service ID already exists. Check the catalog before submitting again."
		}
		s.adminFormError(w, r, "services", status, field, message)
		return
	}
	redirectAdmin(w, r, "service-created")
}

func (s *Server) createProfileForm(w http.ResponseWriter, r *http.Request) {
	if s.profiles == nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusServiceUnavailable,
			"form",
			"Access profiles are not configured.",
		)
		return
	}
	if strings.TrimSpace(r.FormValue("name")) == "" {
		s.adminFormError(w, r, "access", http.StatusBadRequest, "name", "Enter a profile name.")
		return
	}
	serviceIDs := formSelections(r, "service_ids")
	if len(serviceIDs) == 0 {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"service_ids",
			"Choose at least one service.",
		)
		return
	}
	id, err := browserFormID(r)
	if err != nil {
		status, message := browserIDError(err)
		s.adminFormError(w, r, "access", status, "id", message)
		return
	}
	profile := profiles.AccessProfile{
		ID:         id,
		Name:       strings.TrimSpace(r.FormValue("name")),
		DeviceIDs:  formSelections(r, "device_ids"),
		ServiceIDs: serviceIDs,
	}
	if _, err = s.profiles.Create(r.Context(), profile); err != nil {
		status, field, message := http.StatusServiceUnavailable, "form", "The profile could not be saved. Try again shortly."
		switch {
		case errors.Is(err, profiles.ErrDuplicateID):
			status, field, message = http.StatusConflict, "id", "This profile ID already exists. Check the profiles before submitting again."
		case errors.Is(err, profiles.ErrServiceNotFound):
			status, field, message = http.StatusBadRequest, "service_ids", "A selected service is no longer available. Review your selection."
		case errors.Is(err, profiles.ErrDeviceNotAllowed):
			status, field, message = http.StatusBadRequest, "device_ids", "Choose only active registered devices."
		}
		s.adminFormError(w, r, "access", status, field, message)
		return
	}
	redirectAdmin(w, r, "profile-created")
}

func unsafeAppScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "javascript", "data", "file", "vbscript":
		return true
	default:
		return false
	}
}
