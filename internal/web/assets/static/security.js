"use strict";

(() => {
  let generation = 0;
  let busy = false;
  const operations = new Set();
  const root = () => document.querySelector("[data-account-security]");
  const bytes = (value) =>
    Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const encoded = (value) =>
    btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  function clearSecrets(panel) {
    if (!panel) return;
    for (const selector of ["[data-totp-secret]", "[data-recovery-values]"]) {
      const value = panel.querySelector(selector);
      if (value) value.textContent = "";
    }
    for (const selector of ["[data-totp-enrollment]", "[data-security-codes]"]) {
      const section = panel.querySelector(selector);
      if (section) section.hidden = true;
    }
    panel.querySelectorAll('input[name="code"]').forEach((input) => {
      input.value = "";
    });
  }

  function depart() {
    generation++;
    busy = false;
    operations.forEach((operation) => operation.abort());
    operations.clear();
    clearSecrets(root());
  }

  function enhance() {
    const panel = root();
    if (!panel) return;
    panel.querySelectorAll("fieldset").forEach((fieldset) => {
      fieldset.disabled = panel.dataset.recent !== "true";
    });
  }

  function announce(panel, message, error = false) {
    const status = panel.querySelector("[data-security-status]");
    status.textContent = message;
    status.classList.toggle("error-text", error);
    status.focus();
  }

  async function request(path, body, operation, panel) {
    const timeout = setTimeout(() => operation.abort(), 15000);
    try {
      const response = await fetch(`/api/v1/admin/account/${path}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": panel.dataset.csrf },
        body: JSON.stringify(body),
        cache: "no-store",
        signal: operation.signal,
      });
      if (!response.ok) {
        if (response.status === 401)
          throw new Error("Your session ended. Sign in again to continue.");
        if (response.status === 403)
          throw new Error("Sign in again before changing security settings.");
        if (response.status === 409)
          throw new Error("Keep another active method. The requested change is unavailable.");
        if (response.status === 429)
          throw new Error("Too many requests. Wait a minute and try again.");
        throw new Error("Account security is temporarily unavailable. Try again shortly.");
      }
      return response.status === 204 ? null : await response.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("[data-security-action]")) return;
    event.preventDefault();
    const panel = form.closest("[data-account-security]");
    if (!panel || busy || panel.dataset.recent !== "true") return;
    const button = form.querySelector('button[type="submit"]');
    if (button.disabled) return;
    const action = form.dataset.securityAction;
    const epoch = generation;
    const operation = new AbortController();
    const current = () => epoch === generation && panel === root();
    const label = button.textContent;
    let ambiguous = false;
    busy = true;
    operations.add(operation);
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    announce(panel, "Updating account security…");
    try {
      if (action === "passkeys/add") {
        if (!window.PublicKeyCredential)
          throw new Error(
            "This browser cannot create passkeys. Use a supported browser or set up an authenticator.",
          );
        const begin = await request(
          "passkeys/begin",
          { name: form.elements.namedItem("name").value },
          operation,
          panel,
        );
        if (!current()) return;
        // Manual byte conversion also supports Safari versions without the
        // newer JSON option helpers. Security keys remain eligible.
        const options = begin.options.publicKey;
        options.challenge = bytes(options.challenge);
        options.user.id = bytes(options.user.id);
        options.excludeCredentials?.forEach((item) => {
          item.id = bytes(item.id);
        });
        const credential = await navigator.credentials.create({
          publicKey: options,
          signal: operation.signal,
        });
        if (!current()) return;
        if (!credential) throw new Error("No passkey was created. Try again.");
        ambiguous = true;
        await request(
          "passkeys/finish",
          {
            ceremony_id: begin.ceremony_id,
            response: {
              id: credential.id,
              rawId: encoded(credential.rawId),
              type: credential.type,
              response: {
                attestationObject: encoded(credential.response.attestationObject),
                clientDataJSON: encoded(credential.response.clientDataJSON),
                transports: credential.response.getTransports?.() || [],
              },
            },
          },
          operation,
          panel,
        );
      } else if (action === "totp/begin") {
        const enrollment = await request(action, {}, operation, panel);
        if (!current()) return;
        panel.querySelector("[data-totp-secret]").textContent = enrollment.secret;
        panel.querySelector("[data-totp-enrollment]").hidden = false;
        button.hidden = true;
        announce(panel, "Enter the setup key in your authenticator, then confirm a code.");
        return;
      } else if (action === "recovery-codes") {
        // A lost response can still have committed a replacement. Never retry
        // automatically or retain a previously displayed invalid set.
        panel.querySelector("[data-recovery-values]").textContent = "";
        panel.querySelector("[data-security-codes]").hidden = true;
        const result = await request(action, {}, operation, panel);
        if (!current()) return;
        panel.querySelector("[data-recovery-values]").textContent = result.codes.join("\n");
        panel.querySelector("[data-security-codes]").hidden = false;
        announce(panel, "New recovery codes are ready. Save them before leaving this page.");
        return;
      } else {
        const body = {};
        if (action === "totp/confirm") {
          const input = form.elements.namedItem("code");
          body.code = input.value.trim();
          input.value = "";
        }
        if (action === "passkeys/remove") body.id = form.elements.namedItem("id").value;
        await request(action, body, operation, panel);
      }
      if (current()) {
        clearSecrets(panel);
        location.replace("/admin/login?return_to=security");
      }
    } catch (error) {
      if (!current()) return;
      const cancelled = error.name === "NotAllowedError";
      announce(
        panel,
        ambiguous
          ? "The passkey may have been saved. Reload and review your methods before trying again."
          : cancelled
            ? "Passkey prompt cancelled. You can try again."
            : error.name === "AbortError" || error instanceof TypeError
              ? "Unable to connect. Check the service and try again."
              : error.message,
        !cancelled,
      );
    } finally {
      operations.delete(operation);
      if (current()) {
        busy = false;
        button.disabled = ambiguous;
        button.textContent = label;
        button.removeAttribute("aria-busy");
      }
    }
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-clear-recovery]")) return;
    const panel = root();
    clearSecrets(panel);
    if (panel) announce(panel, "Recovery codes cleared from this page.");
  });
  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.detail?.target?.id === "admin-shell") depart();
  });
  document.addEventListener("htmx:afterSwap", enhance);
  document.addEventListener("htmx:historyRestore", enhance);
  window.addEventListener("pagehide", depart);
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) location.reload();
  });
  enhance();
})();
