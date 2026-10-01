"use strict";

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

async function authRequest(path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`/api/v1/auth/${path}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      signal: controller.signal,
    });
    if (!response.ok) {
      if (response.status === 429)
        throw new Error("Too many attempts. Wait a minute and try again.");
      if (response.status === 503)
        throw new Error("Sign-in is temporarily unavailable. Try again shortly.");
      if (response.status === 401)
        throw new Error("We could not verify your passkey or recovery code. Please try again.");
      throw new Error("The request could not be completed. Reload this page and try again.");
    }
    return response.status === 204 ? null : response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function runAuth(button, action) {
  if (button.disabled) return;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  showStatus("Follow the prompt on your device…");
  try {
    await action();
  } catch (error) {
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

document.querySelector("#passkey")?.addEventListener("click", (event) => {
  runAuth(event.currentTarget, async () => {
    if (!window.PublicKeyCredential)
      throw new Error(
        "This browser does not support passkeys. Use a supported browser or a recovery code.",
      );
    const begin = await authRequest("login/begin");
    const options = begin.options.publicKey;
    options.challenge = decodeBytes(options.challenge);
    options.allowCredentials?.forEach((item) => {
      item.id = decodeBytes(item.id);
    });
    const credential = await navigator.credentials.get({ publicKey: options });
    if (!credential) throw new Error("No passkey was selected. Try again.");
    await authRequest("login/finish", {
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
    location.assign("/admin/");
  });
});

document.querySelector("#bootstrap")?.addEventListener("click", (event) => {
  const button = event.currentTarget;
  runAuth(button, async () => {
    if (!window.PublicKeyCredential)
      throw new Error(
        "This browser does not support passkeys. Open this page in a supported browser.",
      );
    const begin = await authRequest("bootstrap/begin");
    const options = begin.options.publicKey;
    options.challenge = decodeBytes(options.challenge);
    options.user.id = decodeBytes(options.user.id);
    options.excludeCredentials?.forEach((item) => {
      item.id = decodeBytes(item.id);
    });
    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) throw new Error("No passkey was created. Try again.");
    const result = await authRequest("bootstrap/finish", {
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
    location.assign("/admin/");
  });
});
// Enable secret entry only after submission is intercepted. A failed or late
// script leaves both controls disabled and a non-GET form fallback.
if (recoveryForm) recoveryForm.querySelector("fieldset").disabled = false;

document.querySelector("#codes-saved")?.addEventListener("click", () => {
  codesValue.textContent = "";
  location.replace("/admin/");
});
window.addEventListener("pagehide", () => {
  if (codesValue) codesValue.textContent = "";
  if (codesSection) codesSection.hidden = true;
  const input = document.querySelector("#recovery-code");
  if (input) input.value = "";
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) location.reload();
});
