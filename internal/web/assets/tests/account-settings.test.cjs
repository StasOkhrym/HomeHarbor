const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

function settingsPage(fetchImpl, recent = true) {
  const events = new Map();
  const windowEvents = new Map();
  const requests = [];
  const navigations = [];
  const fieldset = { disabled: true };
  const email = { value: "helper@example.test", type: "email" };
  const status = { textContent: "", classList: { toggle() {} }, focus() {} };
  const panel = {
    dataset: { csrf: "owner-csrf", recent: String(recent) },
    querySelector: () => status,
    querySelectorAll: (selector) => (selector === "fieldset" ? [fieldset] : [email]),
  };
  const button = { disabled: false, textContent: "Send", setAttribute() {}, removeAttribute() {} };
  const context = {
    document: {
      querySelector: () => panel,
      addEventListener: (name, callback) => events.set(name, callback),
    },
    window: { addEventListener: (name, callback) => windowEvents.set(name, callback) },
    location: { replace: (url) => navigations.push(url), reload() {} },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return fetchImpl(url, options);
    },
    AbortController,
    setTimeout,
    clearTimeout,
    TypeError,
  };

  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../static/account-settings.js"), "utf8"),
    context,
  );

  const submit = async (action) => {
    const form = {
      dataset: { accountAction: action },
      matches: (selector) => selector === "[data-account-action]",
      closest: () => panel,
      querySelector: () => button,
      elements: {
        namedItem: (name) =>
          name === "email" ? email : name === "id" ? { value: "helper-id" } : { checked: true },
      },
    };

    await events.get("submit")({ target: form, preventDefault() {} });
  };

  return { events, windowEvents, requests, navigations, fieldset, email, status, submit };
}

test("owner settings use fixed JSON/CSRF actions and keep recipient out of URLs", async () => {
  const page = settingsPage(async () => ({
    status: 201,
    ok: true,
    json: async () => {
      throw new Error("PRIVATE_REPLY");
    },
  }));

  assert.equal(page.fieldset.disabled, false);

  await page.submit("invite");

  assert.equal(page.requests[0].url, "/api/v1/admin/account/admins/invite");
  assert.deepEqual(JSON.parse(page.requests[0].options.body), { email: "helper@example.test" });
  assert.equal(page.requests[0].options.headers["X-CSRF-Token"], "owner-csrf");
  assert.equal(page.requests[0].options.credentials, "same-origin");
  assert.equal(page.email.value, "");
  assert.deepEqual(page.navigations, ["/admin/administrators?notice=administrator_invited"]);
});

test("stale owner settings remain read-only", async () => {
  const page = settingsPage(async () => {
    throw new Error("must not request");
  }, false);

  assert.equal(page.fieldset.disabled, true);

  await page.submit("invite");

  assert.equal(page.requests.length, 0);
});

test("departed owner settings abort and ignore a late mutation reply", async () => {
  let finish;
  const page = settingsPage(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const pending = page.submit("invite");

  page.events.get("htmx:beforeSwap")({ detail: { target: { id: "admin-shell" } } });

  assert.equal(page.requests[0].options.signal.aborted, true);
  assert.equal(page.email.value, "");

  finish({ status: 201, ok: true });
  await pending;

  assert.deepEqual(page.navigations, []);
  assert.equal(page.fieldset.disabled, true);
});

test("ambiguous account mutations require review without provider text or blind retry", async () => {
  const page = settingsPage(async () => {
    throw new TypeError("PRIVATE_PROVIDER_REPLY");
  });

  await page.submit("revoke");

  assert.match(page.status.textContent, /Reload/);
  assert.doesNotMatch(page.status.textContent, /PRIVATE/);
  assert.equal(page.fieldset.disabled, true);

  await page.submit("revoke");

  assert.equal(page.requests.length, 1);
  assert.deepEqual(page.navigations, []);
});

test("mail tests send no arbitrary recipient and do not claim delivery from an unexpected response", async () => {
  const page = settingsPage(async () => ({ status: 200, ok: true, redirected: true }));

  await page.submit("mail-test");

  assert.equal(page.requests[0].url, "/api/v1/admin/account/mail/test");
  assert.deepEqual(JSON.parse(page.requests[0].options.body), {});
  assert.deepEqual(page.navigations, []);
  assert.equal(page.fieldset.disabled, true);
  assert.match(page.status.textContent, /Reload/);
});
