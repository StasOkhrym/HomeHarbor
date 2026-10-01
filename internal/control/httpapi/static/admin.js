"use strict";

function browserMessage(message) {
  const status = document.querySelector("#browser-status");
  if (status) {
    status.textContent = message;
    status.hidden = false;
    status.focus();
  }
}

// Event delegation survives HTMX GET navigation; forms still use ordinary
// browser POSTs, so their validation/confirmation never relies on JavaScript.
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (form.matches("[data-logout]")) {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const response = await fetch("/api/v1/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(new FormData(form)),
      });
      if (!response.ok) throw new Error("Sign-out could not be completed. Try again.");
      location.replace("/admin/login");
    } catch (error) {
      browserMessage(error.message);
      button.disabled = false;
    }
    return;
  }
  const submitter = event.submitter;
  if (submitter) {
    // Keep the successful submit control in the request. Disabling it here
    // would drop confirmation/action values from normal form submissions.
    submitter.setAttribute("aria-busy", "true");
    submitter.textContent = "Working…";
  }
});

document.addEventListener("htmx:afterSwap", () => {
  enhancePolicyEditor();
  const heading = document.querySelector("#page-title");
  heading?.focus({ preventScroll: true });
  const navigation = document.querySelector(".mobile-nav");
  if (navigation) navigation.open = false;
});

function enhancePolicyEditor() {
  document.querySelectorAll("[data-add-rule], [data-remove-rule]").forEach((button) => {
    button.hidden = false;
  });
}
document.addEventListener("click", (event) => {
  if (event.target.closest("[data-add-rule]")) {
    const form = event.target.closest("[data-policy-editor]");
    const row = form.querySelector("[data-policy-template]").content.cloneNode(true);
    form.querySelector("[data-policy-rows]").append(row);
    enhancePolicyEditor();
    form.querySelector("[data-policy-rows]").lastElementChild.querySelector("select").focus();
  }

  if (event.target.closest("[data-remove-rule]")) {
    const form = event.target.closest("[data-policy-editor]");
    event.target.closest("[data-policy-row]").remove();
    form.querySelector("[data-add-rule]").focus();
  }
});
enhancePolicyEditor();
const invalidField = document.querySelector('[aria-invalid="true"]');
if (invalidField) invalidField.focus();
else document.querySelector("[data-form-error]")?.focus();
function pageLoadError(event) {
  if (event.detail.xhr.status === 401) {
    location.assign("/admin/login");
  } else {
    browserMessage("This page could not be loaded. Reload or try again shortly.");
  }
}
document.addEventListener("htmx:responseError", pageLoadError);
// With history caching disabled, Back/Forward uses a separate HTMX loader
// that does not honor HX-Redirect or emit the ordinary responseError event.
document.addEventListener("htmx:historyCacheMissLoadError", pageLoadError);
document.addEventListener("htmx:sendError", () => {
  browserMessage("Unable to connect to control. Check the service and try again.");
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    // Never reload a secret-producing POST from bfcache: it may issue a new
    // token. Return to a safe GET instead, with the old DOM already cleared.
    if (document.body.matches("[data-secret-page]")) location.replace("/admin/invites");
    else location.reload();
  }
});
window.addEventListener("pagehide", () => {
  document.querySelectorAll("[data-secret-value]").forEach((field) => {
    field.value = "";
    field.textContent = "";
  });
});
