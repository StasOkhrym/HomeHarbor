const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const token = "A".repeat(43);
function mailPage(flow, fetchImpl, options = {}) {
  const events = new Map();
  const requests = [];
  const navigations = [];
  const history = [];
  const fields = {
    email: { name: "email", value: "invited@example.test", type: "email" },
    password: { name: "password", value: " private long password ", type: "password" },
    code: { name: "code", value: "123456", type: "text", focus() {} },
    name: { name: "name", value: "iPhone", type: "text" },
  };
  const node = (hidden = false) => ({
    hidden,
    textContent: "",
    classList: { toggle() {} },
    focus() {},
    setAttribute() {},
    removeAttribute() {},
  });
  const nodes = {
    status: node(),
    "mail-title": node(),
    "mail-complete": node(true),
    "complete-title": node(),
    "complete-message": node(),
    "reset-request-panel": node(),
    "reset-password-panel": node(true),
    "enrollment-options": node(),
    "enrollment-totp": node(true),
    "enrollment-secret": node(),
  };
  const names =
    flow === "invitation"
      ? ["accept-invitation"]
      : flow === "reset"
        ? ["request-reset", "reset-password"]
        : flow === "verify"
          ? ["verify-email"]
          : options.enrolling
            ? ["enrollment-passkey", "enrollment-totp-begin", "enrollment-totp-confirm"]
            : ["enrollment-password"];
  const forms = new Map();
  for (const name of names) {
    const listeners = new Map();
    const button = { ...node(), disabled: false };
    let disabled = true;
    const fieldset = {
      get disabled() {
        return disabled;
      },
      set disabled(value) {
        if (!value)
          assert.equal(
            typeof listeners.get("submit"),
            "function",
            "private entry enabled before interception",
          );
        disabled = value;
      },
    };
    const form = {
      id: name,
      listeners,
      button,
      fieldset,
      elements: {
        namedItem(name) {
          return fields[name] || null;
        },
      },
      addEventListener(name, listener) {
        listeners.set(name, listener);
      },
      querySelector(selector) {
        return selector === "fieldset" ? fieldset : selector.includes("button") ? button : null;
      },
      reset() {
        Object.values(fields).forEach((field) => {
          field.value = "";
        });
      },
    };

    forms.set(name, form);
  }

  const root = {
    dataset: {
      mailFlow: flow,
      emailEnabled: String(options.emailEnabled !== false),
      enrolling: String(!!options.enrolling),
    },
    querySelector(selector) {
      return lookup(selector);
    },
    querySelectorAll(selector) {
      if (selector === "fieldset") return [...forms.values()].map((form) => form.fieldset);
      if (selector === "form") return [...forms.values()];

      return Object.values(fields);
    },
  };
  function lookup(selector) {
    if (selector === "#mail-flow") return root;
    if (!selector.startsWith("#")) return null;

    const id = selector.slice(1);
    if (forms.has(id)) return forms.get(id);
    if (nodes[id]) return nodes[id];
    if (["current-password", "new-password"].includes(id)) return fields.password;
    if (id === "one-time-code") return fields.code;

    return null;
  }
  const location = {
    pathname: `/admin/${flow === "reset" ? "reset-password" : flow === "verify" ? "verify-email" : flow === "enrollment" ? "complete-account" : flow}`,
    hash: options.hash === undefined ? `#token=${token}` : options.hash,
    search: options.search || "",
    replace(value) {
      navigations.push(value);
    },
    reload() {},
  };
  const storage = new Proxy(
    {},
    {
      get() {
        throw new Error("private auth state entered browser storage");
      },
    },
  );

  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/auth-ui.js"), "utf8"), {
    document: { querySelector: lookup },
    window: {
      PublicKeyCredential: options.credentialImpl
        ? {
            signalUnknownCredential() {
              throw new Error("provider deletion is forbidden");
            },
          }
        : undefined,
      addEventListener(name, callback) {
        events.set(name, callback);
      },
    },
    navigator: { credentials: { create: options.credentialImpl } },
    location,
    history: {
      replaceState(_state, _title, value) {
        history.push(value);
        location.hash = "";
        location.search = "";
      },
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return fetchImpl(url, options);
    },
    localStorage: storage,
    sessionStorage: storage,
    AbortController,
    setTimeout,
    clearTimeout,
    URLSearchParams,
    atob,
    btoa,
    Uint8Array,
  });
  return {
    events,
    requests,
    navigations,
    history,
    fields,
    forms,
    nodes,
    submit(id) {
      const form = forms.get(id);

      assert.equal(typeof form.listeners.get("submit"), "function", `script did not bind ${id}`);

      return form.listeners.get("submit")({ preventDefault() {}, currentTarget: form });
    },
  };
}
const flush = () => new Promise(setImmediate);

test("invitation scrubs fragment and sends its proof only by explicit POST", async () => {
  const page = mailPage("invitation", async () => ({
    ok: true,
    status: 200,
    json: async () => ({ next: "enrollment" }),
  }));

  assert.deepEqual(page.history, ["/admin/invitation"]);
  assert.equal(page.requests.length, 0);
  assert.equal(page.forms.get("accept-invitation").fieldset.disabled, false);

  await page.submit("accept-invitation");

  assert.equal(page.requests[0].url, "/api/v1/auth/invitation/accept");
  assert.equal(page.requests[0].options.method, "POST");

  const body = JSON.parse(page.requests[0].options.body);

  assert.equal(body.token, token);
  assert.equal(body.email, "invited@example.test");
  assert.equal(body.password, " private long password ");
  assert.equal(page.fields.password.value, "");
  assert.deepEqual(page.navigations, ["/admin/complete-account"]);
});

test("query proof is ignored and cannot trigger an email mutation", async () => {
  const page = mailPage("verify", async () => ({ ok: true, status: 204 }), {
    hash: "",
    search: `?token=${token}`,
  });

  assert.equal(page.requests.length, 0);
  assert.equal(page.forms.get("verify-email").fieldset.disabled, true);
  assert.match(page.nodes.status.textContent, /link/i);

  await page.submit("verify-email");

  assert.equal(page.requests.length, 0);
});

test("reset cancels private work and ignores a reply after leaving", async () => {
  let deliver;
  const page = mailPage(
    "reset",
    () =>
      new Promise((resolve) => {
        deliver = resolve;
      }),
  );
  const pending = page.submit("reset-password");

  await flush();

  assert.equal(page.requests.length, 1);

  page.events.get("pagehide")();

  assert.equal(page.requests[0].options.signal.aborted, true);
  assert.equal(page.fields.password.value, "");

  deliver({ ok: true, status: 204 });
  await pending;

  assert.equal(page.nodes["mail-complete"].hidden, true);
  assert.deepEqual(page.navigations, []);
});

test("departed enrollment cannot receive or retain a setup key", async () => {
  let deliver;
  const page = mailPage(
    "enrollment",
    () =>
      new Promise((resolve) => {
        deliver = resolve;
      }),
    { enrolling: true, hash: "" },
  );
  const pending = page.submit("enrollment-totp-begin");

  await flush();
  page.nodes["enrollment-secret"].textContent = "old-private-key";
  page.events.get("pagehide")();

  assert.equal(page.nodes["enrollment-secret"].textContent, "");

  deliver({ ok: true, status: 200, json: async () => ({ secret: "late-private-key" }) });
  await pending;

  assert.equal(page.nodes["enrollment-secret"].textContent, "");
  assert.equal(page.nodes["enrollment-totp"].hidden, true);
});

test("authenticator setup finishes with fresh password and next-code guidance", async () => {
  const page = mailPage(
    "enrollment",
    async (url) =>
      url.endsWith("/begin")
        ? { ok: true, status: 200, json: async () => ({ secret: "private-key" }) }
        : { ok: true, status: 204 },
    { enrolling: true, hash: "" },
  );

  await page.submit("enrollment-totp-begin");

  assert.equal(page.nodes["enrollment-secret"].textContent, "private-key");

  await page.submit("enrollment-totp-confirm");

  assert.equal(page.nodes["enrollment-secret"].textContent, "");
  assert.equal(page.fields.code.value, "");
  assert.equal(page.nodes["mail-complete"].hidden, false);
  assert.match(page.nodes["complete-message"].textContent, /password/i);
  assert.match(page.nodes["complete-message"].textContent, /(next|new).*code/i);
  assert.deepEqual(page.navigations, []);
});

test("reset request confirmation stays generic and does not repeat the address", async () => {
  const page = mailPage(
    "reset",
    async () => ({ ok: true, status: 202, json: async () => ({ next: "check_inbox" }) }),
    { hash: "" },
  );

  await page.submit("request-reset");

  assert.equal(page.requests[0].url, "/api/v1/auth/password/reset/request");
  assert.equal(page.nodes["mail-complete"].hidden, false);
  assert.doesNotMatch(page.nodes["complete-message"].textContent, /invited@example\.test/);
  assert.deepEqual(page.navigations, []);
});

test("mail never displays private successful-response parse errors", async () => {
  const page = mailPage(
    "reset",
    async () => ({
      ok: true,
      status: 202,
      json: async () => {
        throw new SyntaxError("PRIVATE_RESET_PAYLOAD");
      },
    }),
    { hash: "" },
  );

  await page.submit("request-reset");

  assert.doesNotMatch(page.nodes.status.textContent, /PRIVATE_RESET_PAYLOAD/);
  assert.equal(page.nodes["mail-complete"].hidden, true);
});

test("passkey setup blocks blind retry after an ambiguous save", async () => {
  let created = 0;
  const credential = {
    id: "key",
    type: "public-key",
    rawId: new Uint8Array([1]),
    response: { attestationObject: new Uint8Array([2]), clientDataJSON: new Uint8Array([3]) },
  };
  const page = mailPage(
    "enrollment",
    async (url) =>
      url.endsWith("/begin")
        ? {
            ok: true,
            status: 200,
            json: async () => ({
              ceremony_id: "ceremony",
              options: { publicKey: { challenge: "AQ", user: { id: "Ag" } } },
            }),
          }
        : { ok: false, status: 503, json: async () => ({ error: "PRIVATE_PROVIDER_DETAIL" }) },
    {
      enrolling: true,
      hash: "",
      credentialImpl: async () => {
        created++;
        return credential;
      },
    },
  );

  await page.submit("enrollment-passkey");

  assert.equal(page.forms.get("enrollment-passkey").button.hidden, true);
  assert.match(page.nodes.status.textContent, /reload/i);
  assert.doesNotMatch(page.nodes.status.textContent, /PRIVATE_PROVIDER_DETAIL/);

  await page.submit("enrollment-passkey");

  assert.equal(created, 1);
  assert.equal(page.requests.length, 2);
});
