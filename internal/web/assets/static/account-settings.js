"use strict";

(() => {
  let generation = 0;
  let busy = false;
  let blocked = false;
  const operations = new Set();
  const root = () => document.querySelector("[data-account-settings]");

  function setDisabled(panel) {
    panel?.querySelectorAll("fieldset").forEach((fieldset) => {
      fieldset.disabled = busy || blocked || panel.dataset.recent !== "true";
    });
  }
  function wipeEntry(panel) {
    panel?.querySelectorAll('input[type="email"]').forEach((input) => {
      input.value = "";
    });
  }
  function announce(panel, message) {
    const status = panel.querySelector("[data-account-settings-status]");
    status.textContent = message;
    status.classList.toggle("error-text", true);
    status.focus();
  }
  function depart() {
    generation++;
    blocked = true;
    busy = false;
    operations.forEach((operation) => operation.abort());
    operations.clear();
    wipeEntry(root());
    setDisabled(root());
  }
  function enhance() {
    busy = false;
    blocked = false;
    setDisabled(root());
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("[data-account-action]")) return;

    event.preventDefault();

    const panel = form.closest("[data-account-settings]");
    if (!panel || busy || blocked || panel.dataset.recent !== "true") return;

    const confirmation = form.elements.namedItem("confirmed");
    if (confirmation && !confirmation.checked) return;

    const action = form.dataset.accountAction;
    let path, body, expected, destination;
    if (action === "invite") {
      path = "admins/invite";
      body = { email: form.elements.namedItem("email").value };
      expected = 201;
      destination = "/admin/administrators?notice=administrator_invited";
    } else if (action === "revoke") {
      path = `admins/${encodeURIComponent(form.elements.namedItem("id").value)}/revoke`;
      body = {};
      expected = 204;
      destination = "/admin/administrators?notice=administrator_revoked";
    } else if (action === "mail-test") {
      path = "mail/test";
      body = {};
      expected = 202;
      destination = "/admin/mail?notice=mail_test_queued";
    } else return;

    const epoch = generation;
    const current = () => generation === epoch && panel === root();
    const operation = new AbortController();
    const button = form.querySelector('button[type="submit"]');
    const label = button.textContent;
    const uncertain =
      "The change may have completed. Reload and review the current state before trying again.";
    busy = true;
    operations.add(operation);
    setDisabled(panel);
    button.setAttribute("aria-busy", "true");
    button.textContent = "Working…";
    wipeEntry(panel);

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
      if (!current()) return;
      if (!response.redirected && response.status === expected) {
        blocked = true;
        location.replace(destination);
        return;
      }

      if (response.status === 401) {
        blocked = true;
        location.replace("/admin/login?restart=1");
      } else if (response.status === 403) {
        blocked = true;
        announce(
          panel,
          "Only the owner with a recent sign-in can change these settings. Sign in again.",
        );
      } else if (response.status === 429) {
        announce(panel, "Wait a minute before requesting another change.");
      } else if (response.status === 400 || response.status === 409) {
        announce(panel, "The requested change is unavailable. Review the account and try again.");
      } else {
        blocked = true;
        announce(panel, uncertain);
      }
    } catch {
      if (current()) {
        blocked = true;
        announce(panel, uncertain);
      }
    } finally {
      clearTimeout(timeout);
      operations.delete(operation);
      if (current()) {
        busy = false;
        button.textContent = label;
        button.removeAttribute("aria-busy");
        setDisabled(panel);
      }
    }
  });
  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.detail?.target?.id === "admin-shell") depart();
  });
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.detail?.target?.id === "admin-shell") enhance();
  });
  window.addEventListener("pagehide", depart);
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) location.reload();
  });
  enhance();
})();
