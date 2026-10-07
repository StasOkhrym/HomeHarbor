package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
)

type adminPolicyPreview struct {
	Before    string
	After     string
	RulesJSON string
	Revision  uint64
	Proof     string
	Changes   []adminPolicyChange
}

type adminPolicyChange struct {
	Kind   string
	Before *acl.Rule
	After  *acl.Rule
}

func policyChanges(before, after []acl.Rule) []adminPolicyChange {
	old := make(map[string]acl.Rule, len(before))
	for _, rule := range before {
		old[rule.ID] = rule
	}
	var changes []adminPolicyChange
	for _, rule := range after {
		previous, exists := old[rule.ID]
		if !exists {
			changes = append(changes, adminPolicyChange{Kind: "Added", After: &rule})
		} else if previous != rule {
			changes = append(
				changes,
				adminPolicyChange{Kind: "Modified", Before: &previous, After: &rule},
			)
		}
		delete(old, rule.ID)
	}
	// Keep removals in stored order rather than random map iteration.
	for _, rule := range before {
		if _, exists := old[rule.ID]; exists {
			changes = append(changes, adminPolicyChange{Kind: "Removed", Before: &rule})
		}
	}
	return changes
}

type browserAction struct {
	Operation string     `json:"operation"`
	Target    string     `json:"target,omitempty"`
	Revision  uint64     `json:"revision"`
	Rules     []acl.Rule `json:"rules,omitempty"`
}

func policyFormRules(r *http.Request) ([]acl.Rule, error) {
	if r.FormValue("editor") != "structured" {
		if !strings.HasPrefix(strings.TrimSpace(r.FormValue("rules")), "[") {
			return nil, errors.New("enter a JSON array of rules (use [] to deny everything)")
		}

		var rules []acl.Rule

		if err := json.Unmarshal([]byte(r.FormValue("rules")), &rules); err != nil {
			return nil, errors.New("enter a JSON array of rules")
		}

		return rules, nil
	}

	_ = r.ParseForm()
	count := len(r.PostForm["destination"])
	keys := []string{"rule_id", "source_device_id", "protocol", "port_from", "port_to"}
	for _, key := range keys {
		if len(r.PostForm[key]) != count {
			return nil, errors.New("rule fields are incomplete")
		}
	}

	rules := make([]acl.Rule, 0, count)
	for index := range count {
		destination := strings.TrimSpace(r.PostForm["destination"][index])
		source := r.PostForm["source_device_id"][index]
		if destination == "" && source == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(destination)
		if err != nil {
			return nil, fmt.Errorf("rule %d needs a valid CIDR", index+1)
		}

		from, err := strconv.ParseUint(r.PostForm["port_from"][index], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("rule %d needs a valid start port", index+1)
		}

		to, err := strconv.ParseUint(r.PostForm["port_to"][index], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("rule %d needs a valid end port", index+1)
		}

		id := strings.TrimSpace(r.PostForm["rule_id"][index])
		if id == "" {
			id, err = newBrowserID()
			if err != nil {
				return nil, errors.New("a rule ID could not be generated")
			}
		}

		rules = append(rules, acl.Rule{
			ID:             id,
			SourceDeviceID: source,
			Destination:    prefix,
			Protocol:       acl.Protocol(r.PostForm["protocol"][index]),
			PortFrom:       uint16(from),
			PortTo:         uint16(to),
		})
	}

	return rules, nil
}

func (s *Server) previewPolicyForm(w http.ResponseWriter, r *http.Request) {
	if s.policy == nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusServiceUnavailable,
			"rules",
			"Policy is not configured.",
		)
		return
	}
	current, err := s.policy.Latest(r.Context())
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusServiceUnavailable,
			"rules",
			"Current policy could not be loaded. No preview is available.",
		)
		return
	}
	rules, err := policyFormRules(r)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"Check the rules: "+err.Error()+".",
		)
		return
	}
	proposed, err := (acl.Compiler{}).Compile(current.Revision+1, rules)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"Check rule IDs, source devices, non-default CIDRs, TCP/UDP and port ranges.",
		)
		return
	}
	if proposed.Rules == nil {
		proposed.Rules = []acl.Rule{}
	}
	model, _ := s.loadAdminPage(r, "access")
	if s.actionConfirmation == nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusServiceUnavailable,
			"rules",
			"Policy confirmation is not configured.",
		)
		return
	}
	payload, _ := json.Marshal(
		browserAction{
			Operation: "replace-policy",
			Revision:  current.Revision,
			Rules:     proposed.Rules,
		},
	)
	before, _ := json.MarshalIndent(current.Rules, "", "  ")
	after, _ := json.MarshalIndent(proposed.Rules, "", "  ")
	model.Preview = &adminPolicyPreview{
		Before:    string(before),
		After:     string(after),
		RulesJSON: string(after),
		Revision:  current.Revision,
		Proof:     s.actionConfirmation.SignAction(csrfFormToken(r), payload),
		Changes:   policyChanges(current.Rules, proposed.Rules),
	}
	s.renderAdmin(w, http.StatusOK, model)
}

func (s *Server) replacePolicyForm(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("confirmed") != "yes" {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"Preview and confirm the policy replacement first.",
		)
		return
	}
	if s.policy == nil || s.actionConfirmation == nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusServiceUnavailable,
			"rules",
			"Policy confirmation is unavailable.",
		)
		return
	}
	revision, err := strconv.ParseUint(r.FormValue("revision"), 10, 64)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"The preview revision is invalid.",
		)
		return
	}
	rules, err := policyFormRules(r)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"The preview rules are invalid.",
		)
		return
	}
	compiled, err := (acl.Compiler{}).Compile(revision+1, rules)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusBadRequest,
			"rules",
			"The preview rules are invalid.",
		)
		return
	}
	payload, _ := json.Marshal(
		browserAction{Operation: "replace-policy", Revision: revision, Rules: compiled.Rules},
	)
	if !s.actionConfirmation.VerifyAction(csrfFormToken(r), payload, r.FormValue("proof")) {
		s.adminFormError(
			w,
			r,
			"access",
			http.StatusForbidden,
			"rules",
			"The preview changed or belongs to another session. Preview again.",
		)
		return
	}
	if _, err = s.policy.ReplaceIfRevision(r.Context(), revision, compiled.Rules); err != nil {
		status, message := http.StatusServiceUnavailable, "The policy could not be saved. Try again shortly."
		if errors.Is(err, policy.ErrRevisionConflict) {
			status, message = http.StatusConflict, "Policy changed after your preview. Review the current policy and preview again."
		}
		s.adminFormError(w, r, "access", status, "rules", message)
		return
	}
	redirectAdmin(w, r, "policy-updated")
}

func (s *Server) revokeDeviceForm(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("confirmed") != "yes" {
		s.adminFormError(
			w,
			r,
			"devices",
			http.StatusBadRequest,
			"form",
			"Review the device details and confirm credential revoke first.",
		)
		return
	}
	if s.actionConfirmation == nil || s.devices == nil {
		s.adminFormError(
			w,
			r,
			"devices",
			http.StatusServiceUnavailable,
			"form",
			"Credential revoke is unavailable.",
		)
		return
	}
	payload, _ := json.Marshal(browserAction{Operation: "revoke-device", Target: r.PathValue("id")})
	if !s.actionConfirmation.VerifyAction(csrfFormToken(r), payload, r.FormValue("proof")) {
		s.adminFormError(
			w,
			r,
			"devices",
			http.StatusForbidden,
			"form",
			"This confirmation is invalid. Reload the device details.",
		)
		return
	}
	if err := s.devices.Revoke(r.Context(), r.PathValue("id")); err != nil {
		s.adminFormError(
			w,
			r,
			"devices",
			http.StatusServiceUnavailable,
			"form",
			"Credentials could not be revoked. Reload and check the device.",
		)
		return
	}
	if s.invalidateDevice != nil {
		s.invalidateDevice(r.PathValue("id"))
	}
	redirectAdmin(w, r, "device-revoked")
}
