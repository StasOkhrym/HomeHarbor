"use strict";

let authAlive = true;
const authOperations = new Set();
function requireActivePage() {
  if (!authAlive) {
    const error = new Error("Sign-in page closed");
    error.name = "AbortError";
    throw error;
  }
}
async function credentialRequest(kind, publicKey) {
  requireActivePage();

  const controller = new AbortController();
  authOperations.add(controller);

  try {
    const credential = await navigator.credentials[kind]({ publicKey, signal: controller.signal });
    requireActivePage();
    return credential;
  } finally {
    authOperations.delete(controller);
  }
}

const returnToSecurity =
  document.querySelector("[data-login-return]")?.dataset.loginReturn === "security";
const signInURL = returnToSecurity ? "/admin/login?return_to=security" : "/admin/login";
const completedURL = returnToSecurity ? "/admin/security" : "/admin/";
const statusElement = document.querySelector("#status");
const codesSection = document.querySelector("#recovery-codes");
const codesValue = document.querySelector("#codes-value");
const decodeBytes = (value) =>
  Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (character) =>
    character.charCodeAt(0),
  );
const encodeBytes = (value) =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

function showStatus(message, isError = false) {
  if (!statusElement) return;

  statusElement.textContent = message;
  statusElement.classList.toggle("error-text", isError);
}

async function authRequest(path, body, csrf) {
  requireActivePage();

  const controller = new AbortController();
  authOperations.add(controller);

  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`/api/v1/auth/${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(csrf ? { "X-CSRF-Token": csrf } : {}) },
      body: JSON.stringify(body || {}),
      signal: controller.signal,
    });
    requireActivePage();
    if (!response.ok) {
      // Only the post-registration boundary can assert that the passkey exists.
      // Never echo arbitrary server error text or store recovery material.
      const failure = await response.json().catch(() => ({}));
      if (
        path === "bootstrap/finish" &&
        ["bootstrap_recovery_unavailable", "bootstrap_session_unavailable"].includes(failure.code)
      ) {
        const error = new Error(
          "Your passkey was saved, but setup could not finish. Reload this page and sign in with your passkey. Recovery codes were not delivered.",
        );
        error.bootstrapIncomplete = true;
        throw error;
      }
      if (response.status === 429)
        throw new Error("Too many attempts. Wait a minute and try again.");
      if (response.status === 503)
        throw new Error("Sign-in is temporarily unavailable. Try again shortly.");
      if (response.status === 401)
        throw new Error("We could not verify your details. Please try again.");

      throw new Error("The request could not be completed. Reload this page and try again.");
    }

    const result =
      response.status === 204
        ? null
        : await response.json().catch(() => {
            throw new Error(
              "The response could not be read. Reload this page before trying again.",
            );
          });
    requireActivePage();
    return result;
  } finally {
    clearTimeout(timeout);
    authOperations.delete(controller);
  }
}

async function runAuth(button, action, progress = "Checking your details…") {
  if (button.disabled) return;

  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  showStatus(progress);

  try {
    await action();
  } catch (error) {
    if (!authAlive) return;

    if (error.bootstrapIncomplete || error.registrationIncomplete) button.hidden = true;
    const cancelled = error.name === "NotAllowedError";
    const networkFailure = error.name === "AbortError" || error instanceof TypeError;
    showStatus(
      cancelled
        ? "Passkey prompt cancelled. You can try again."
        : networkFailure
          ? "Unable to connect. Check the service and try again."
          : error.message,
      !cancelled,
    );
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}

async function passkeyProof(beginPath, finishPath) {
  if (!window.PublicKeyCredential)
    throw new Error(
      "This browser does not support passkeys. Use a supported browser or a recovery code.",
    );

  const begin = await authRequest(beginPath);
  const options = begin.options.publicKey;
  options.challenge = decodeBytes(options.challenge);
  options.allowCredentials?.forEach((item) => {
    item.id = decodeBytes(item.id);
  });

  const credential = await credentialRequest("get", options);
  if (!credential) throw new Error("No passkey was selected. Try again.");

  await authRequest(finishPath, {
    ...(finishPath === "factor" ? { method: "passkey" } : {}),
    ceremony_id: begin.ceremony_id,
    response: {
      id: credential.id,
      rawId: encodeBytes(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: encodeBytes(credential.response.authenticatorData),
        clientDataJSON: encodeBytes(credential.response.clientDataJSON),
        signature: encodeBytes(credential.response.signature),
        userHandle: credential.response.userHandle
          ? encodeBytes(credential.response.userHandle)
          : null,
      },
    },
  });
}
document.querySelector("#passkey")?.addEventListener("click", (event) =>
  runAuth(event.currentTarget, async () => {
    await passkeyProof("login/begin", "login/finish");
    location.replace(signInURL);
  }),
);
document.querySelector("#factor-passkey")?.addEventListener("click", (event) =>
  runAuth(event.currentTarget, async () => {
    await passkeyProof("passkey/begin", "factor");
    location.replace(completedURL);
  }),
);

async function registerPasskey(beginPath, finishPath, body = {}) {
  if (!window.PublicKeyCredential)
    throw new Error(
      "This browser does not support passkeys. Use an authenticator app or a supported browser.",
    );

  const begin = await authRequest(beginPath, body);
  const options = begin.options.publicKey;
  options.challenge = decodeBytes(options.challenge);
  options.user.id = decodeBytes(options.user.id);
  options.excludeCredentials?.forEach((item) => {
    item.id = decodeBytes(item.id);
  });

  const credential = await credentialRequest("create", options);
  if (!credential) throw new Error("No passkey was created. Try again.");

  try {
    return await authRequest(finishPath, {
      ceremony_id: begin.ceremony_id,
      response: {
        id: credential.id,
        rawId: encodeBytes(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: encodeBytes(credential.response.attestationObject),
          clientDataJSON: encodeBytes(credential.response.clientDataJSON),
        },
      },
    });
  } catch (error) {
    if (finishPath === "enrollment/passkey/finish") {
      const failure = new Error(
        "Your passkey was created, but we could not confirm it was saved. Reload this page; if setup is complete, sign in. Do not create another passkey yet.",
      );
      failure.registrationIncomplete = true;
      throw failure;
    }

    throw error;
  }
}

document.querySelector("#bootstrap")?.addEventListener("click", (event) => {
  const button = event.currentTarget;
  runAuth(button, async () => {
    const result = await registerPasskey("bootstrap/begin", "bootstrap/finish");
    // Plaintext codes belong only to this document, never browser storage.
    // pagehide also clears them before a bfcache navigation can preserve them.
    codesValue.textContent = result.recovery_codes.join("\n");
    codesSection.hidden = false;
    button.hidden = true;
    showStatus("Your passkey is ready. Save the recovery codes before continuing.");
  });
});

const recoveryForm = document.querySelector("#recovery");
recoveryForm?.addEventListener("submit", (event) => {
  event.preventDefault();

  const form = event.currentTarget;
  const codeInput = form.elements.namedItem("code");
  const code = codeInput.value.trim();
  codeInput.value = "";
  runAuth(form.querySelector("button"), async () => {
    await authRequest("recovery", { code });
    location.replace(signInURL);
  });
});
// Enable secret entry only after submission is intercepted. A failed or late
// script leaves both controls disabled and a non-GET form fallback.
if (recoveryForm) recoveryForm.querySelector("fieldset").disabled = false;

document.querySelector("#codes-saved")?.addEventListener("click", () => {
  codesValue.textContent = "";
  location.replace(signInURL);
});

function bindPasswordForm(selector, path) {
  const form = document.querySelector(selector);
  if (!form) return;

  form.addEventListener("submit", (event) => {
    event.preventDefault();

    const password = form.elements.namedItem("password");
    const body = { email: form.elements.namedItem("email").value, password: password.value };
    const csrf = form.elements.namedItem("_csrf")?.value;
    password.value = "";
    return runAuth(form.querySelector('button[type="submit"]'), async () => {
      await authRequest(path, body, csrf);
      location.replace(signInURL);
    });
  });
  form.querySelector("fieldset").disabled = false;
}
bindPasswordForm("#password-login", "password");
bindPasswordForm("#owner-password", "owner/password");

for (const [selector, method] of [
  ["#factor-code", "totp"],
  ["#factor-recovery", "recovery"],
]) {
  const form = document.querySelector(selector);
  if (!form) continue;
  form.addEventListener("submit", (event) => {
    event.preventDefault();

    const input = form.elements.namedItem("code");
    const code = input.value.trim();
    input.value = "";
    return runAuth(form.querySelector('button[type="submit"]'), async () => {
      await authRequest("factor", { method, code });
      location.replace(completedURL);
    });
  });
  form.querySelector("fieldset").disabled = false;
}
for (const id of ["current-password", "new-password"]) {
  const input = document.querySelector(`#${id}`);
  const toggle = document.querySelector(`#toggle-${id}`);
  toggle?.addEventListener("click", () => {
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.textContent = visible ? "Hide password" : "Show password";
  });
}
window.addEventListener("pagehide", () => {
  authAlive = false;
  authOperations.forEach((operation) => operation.abort());
  authOperations.clear();
  if (codesValue) codesValue.textContent = "";
  if (codesSection) codesSection.hidden = true;
  const input = document.querySelector("#recovery-code");
  if (input) input.value = "";
  clearMailSecrets();
  refreshMailControls();
  for (const selector of [
    "#password-login",
    "#owner-password",
    "#factor-code",
    "#factor-recovery",
  ]) {
    const form = document.querySelector(selector);
    const secret = form?.elements.namedItem(selector.startsWith("#factor-") ? "code" : "password");
    if (secret) secret.value = "";
  }
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) location.reload();
});

// Public account flows use the same bounded requests and native credential
// lifetime as sign-in. Link proof stays in this document, never browser storage.
const mailRoot = document.querySelector("#mail-flow");
const mailBindings = new Map();
let mailLinkToken = "";
let mailBusy = false;
let mailComplete = false;
let mailLocked = false;
let mailTOTPReady = false;
let mailFocus = null;

function clearMailSecrets() {
  mailLinkToken = "";
  if (!mailRoot) return;

  const key = mailRoot.querySelector("#enrollment-secret");
  if (key) key.textContent = "";
  const section = mailRoot.querySelector("#enrollment-totp");
  if (section) section.hidden = true;
  for (const form of mailBindings.keys()) {
    for (const name of ["password", "code"]) {
      const input = form.elements.namedItem(name);
      if (input) input.value = "";
    }
  }
}
function refreshMailControls() {
  for (const [form, allowed] of mailBindings) {
    form.querySelector("fieldset").disabled =
      !authAlive || mailBusy || mailComplete || mailLocked || !allowed();
  }
}
function mailAction(button, action, progress) {
  if (!authAlive || mailBusy || mailComplete || mailLocked || button.disabled) return;

  mailBusy = true;
  refreshMailControls();
  return runAuth(button, action, progress).finally(() => {
    mailBusy = false;
    refreshMailControls();
    if (authAlive && mailFocus && !mailComplete && !mailLocked) mailFocus.focus();
    mailFocus = null;
  });
}
function bindMailForm(id, action, allowed = () => true) {
  const form = mailRoot.querySelector(`#${id}`);
  if (!form) return;

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!allowed() || !authAlive || mailBusy || mailComplete || mailLocked) return;

    return mailAction(
      form.querySelector('button[type="submit"]'),
      () => action(form),
      "Updating your account…",
    );
  });
  mailBindings.set(form, allowed);
}
function privateField(form, name) {
  const input = form.elements.namedItem(name);
  const value = input.value;
  input.value = "";
  return value;
}
function completeMail(title, message) {
  requireActivePage();
  mailComplete = true;
  clearMailSecrets();
  for (const id of ["enrollment-options", "reset-request-panel", "reset-password-panel"]) {
    const section = mailRoot.querySelector(`#${id}`);
    if (section) section.hidden = true;
  }

  for (const form of mailBindings.keys()) form.hidden = true;

  mailRoot.querySelector("#complete-title").textContent = title;
  mailRoot.querySelector("#complete-message").textContent = message;
  mailRoot.querySelector("#mail-complete").hidden = false;
  showStatus(title);
  refreshMailControls();
  mailRoot.querySelector("#complete-title").focus();
}
function continueEnrollment(result) {
  if (!["enrollment", "enrollment_password"].includes(result?.next)) {
    throw new Error("We could not confirm the next step. Reload this page before trying again.");
  }

  requireActivePage();
  mailComplete = true;
  clearMailSecrets();
  refreshMailControls();
  location.replace("/admin/complete-account");
}
function initMailFlow() {
  if (!mailRoot) return;

  const flow = mailRoot.dataset.mailFlow;
  const fragment = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  const values = fragment.getAll("token");
  if (values.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(values[0])) mailLinkToken = values[0];

  // Ignore query proof. Remove both fragment and query before private entry is enabled.
  try {
    if (location.hash || location.search) history.replaceState(null, "", location.pathname);
  } catch {
    clearMailSecrets();
    showStatus("Open this link in your browser to continue securely.", true);
    return;
  }

  if (["invitation", "verify"].includes(flow) && !mailLinkToken) {
    showStatus("This link is missing or invalid. Ask your network owner for a new link.", true);
  }

  if (flow === "reset" && mailLinkToken) {
    mailRoot.querySelector("#reset-request-panel").hidden = true;
    mailRoot.querySelector("#reset-password-panel").hidden = false;
    mailRoot.querySelector("#mail-title").textContent = "Choose a new password";
  }

  const linked = () => !!mailLinkToken;
  const setup = () => mailRoot.dataset.enrolling === "true";
  bindMailForm(
    "accept-invitation",
    async (form) => {
      const body = {
        token: mailLinkToken,
        email: form.elements.namedItem("email").value,
        password: privateField(form, "password"),
      };
      continueEnrollment(await authRequest("invitation/accept", body));
    },
    linked,
  );
  bindMailForm(
    "request-reset",
    async (form) => {
      await authRequest("password/reset/request", {
        email: form.elements.namedItem("email").value,
      });
      completeMail(
        "Check your inbox",
        "For an eligible account, a recovery link will arrive by email. Delivery may take a little while. Keep your verification method ready.",
      );
    },
    () => !mailLinkToken && mailRoot.dataset.emailEnabled === "true",
  );
  bindMailForm(
    "reset-password",
    async (form) => {
      await authRequest("password/reset/finish", {
        token: mailLinkToken,
        password: privateField(form, "password"),
      });
      completeMail(
        "Password updated",
        "Sign in with your new password and an existing passkey or authenticator. Your verification methods stay in place.",
      );
    },
    linked,
  );
  bindMailForm(
    "verify-email",
    async () => {
      await authRequest("email/verify", { token: mailLinkToken });
      completeMail(
        "Email confirmed",
        "Your email address is confirmed. You can return to HomeHarbor.",
      );
    },
    linked,
  );
  bindMailForm("enrollment-password", async (form) => {
    continueEnrollment(
      await authRequest("enrollment/password", {
        email: form.elements.namedItem("email").value,
        password: privateField(form, "password"),
      }),
    );
  });
  bindMailForm(
    "enrollment-totp-begin",
    async (form) => {
      const result = await authRequest("enrollment/totp/begin");
      if (typeof result?.secret !== "string" || !result.secret || result.secret.length > 128)
        throw new Error("The setup key could not be read. Reload this page.");

      mailRoot.querySelector("#enrollment-secret").textContent = result.secret;
      mailRoot.querySelector("#enrollment-totp").hidden = false;
      form.hidden = true;
      mailTOTPReady = true;
      mailFocus = mailRoot.querySelector("#one-time-code");
      showStatus("Enter the current code from your authenticator app.");
    },
    setup,
  );
  bindMailForm(
    "enrollment-totp-confirm",
    async (form) => {
      await authRequest("enrollment/totp/confirm", { code: privateField(form, "code").trim() });
      completeMail(
        "You're ready to sign in",
        "Use your password and the next authenticator code to sign in. Wait for a new code in your app.",
      );
    },
    () => setup() && mailTOTPReady,
  );
  bindMailForm(
    "enrollment-passkey",
    async (form) => {
      try {
        await registerPasskey("enrollment/passkey/begin", "enrollment/passkey/finish", {
          name: form.elements.namedItem("name").value,
        });
      } catch (error) {
        if (error.registrationIncomplete) mailLocked = true;
        throw error;
      }

      completeMail(
        "You're ready to sign in",
        "Use your password and this passkey to sign in. You can add more verification methods in account settings.",
      );
    },
    setup,
  );
  refreshMailControls();
}
initMailFlow();
