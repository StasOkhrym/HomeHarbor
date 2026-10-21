const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

// Only browser boundaries are doubled; the shipped script installs the real
// listeners and decides navigation, announcements and secret-field lifecycle.
function adminDocument() {
  const listeners = new Map();
  const navigations = [];
  const status = { hidden: true, textContent: "", focus() {} };
  const heading = {
    focusCount: 0,
    focus() {
      this.focusCount++;
    },
  };
  const navigation = { open: true };
  let policyButtons = [];
  const context = {
    document: {
      addEventListener(name, listener) {
        listeners.set(name, listener);
      },
      querySelector(selector) {
        if (selector === "#browser-status") return status;
        if (selector === "#page-title") return heading;
        if (selector === ".mobile-nav") return navigation;

        return null;
      },
      querySelectorAll(selector) {
        if (selector === "[data-add-rule], [data-remove-rule]") return policyButtons;

        return [];
      },
    },
    window: { addEventListener() {} },
    location: {
      assign(destination) {
        navigations.push(destination);
      },
    },
  };

  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/admin.js"), "utf8"), context);
  return {
    listeners,
    navigations,
    status,
    heading,
    navigation,
    setPolicyButtons(buttons) {
      policyButtons = buttons;
    },
  };
}

test("expired history navigation returns to sign-in", () => {
  const page = adminDocument();

  page.listeners.get("htmx:historyCacheMissLoadError")?.({ detail: { xhr: { status: 401 } } });

  assert.deepEqual(page.navigations, ["/admin/login"]);
});

test("failed history navigation announces that the requested screen was not loaded", () => {
  const page = adminDocument();

  page.listeners.get("htmx:historyCacheMissLoadError")?.({ detail: { xhr: { status: 503 } } });

  assert.equal(page.status.hidden, false);
  assert.notEqual(page.status.textContent, "");
  assert.deepEqual(page.navigations, []);
});

test("background swaps do not steal heading focus or close mobile navigation", () => {
  const page = adminDocument();

  page.listeners.get("htmx:afterSwap")?.({ detail: { target: { id: "activity-feed" } } });

  assert.equal(page.heading.focusCount, 0);
  assert.equal(page.navigation.open, true);

  page.listeners.get("htmx:afterSwap")?.({ detail: { target: { id: "admin-shell" } } });

  assert.equal(page.heading.focusCount, 1);
  assert.equal(page.navigation.open, false);
});

test("history restoration enhances policy controls without moving focus", () => {
  const page = adminDocument();
  const buttons = [{ hidden: true }, { hidden: true }];

  page.setPolicyButtons(buttons);
  page.listeners.get("htmx:historyRestore")?.({ detail: { cacheMiss: true } });

  assert.deepEqual(
    buttons.map((button) => button.hidden),
    [false, false],
  );
  assert.equal(page.heading.focusCount, 0);
  assert.equal(page.navigation.open, true);
});

function activityPage(fetchImpl = async () => ({ ok: false, status: 503 }), options = {}) {
  const kind = options.kind || "activity";
  const listeners = new Map();
  const timers = new Map();
  let nextTimer = 0;
  let activityVisible = true;
  let hidden = false;
  let replacements = 0;
  const requests = [];
  const reused = [];
  function makeFeed(ids, fields = {}) {
    function fieldNode(key, value) {
      return {
        dataset: { reportField: key },
        textContent: value,
        get childNodes() {
          return [
            {
              textContent: this.textContent,
              cloneNode() {
                return { textContent: this.textContent };
              },
            },
          ];
        },
        replaceChildren(...nodes) {
          this.textContent = nodes.map((node) => node.textContent).join("");
        },
      };
    }
    const rows = ids.map((id) => ({
      dataset: { recordId: id, connectionKey: id },
      fieldNodes: Object.fromEntries(
        Object.entries(fields[id] || {}).map(([key, value]) => [key, fieldNode(key, value)]),
      ),
      querySelectorAll() {
        return Object.values(this.fieldNodes);
      },
      querySelector(selector) {
        const key = /data-report-field="([^"]+)"/.exec(selector)?.[1];
        return this.fieldNodes[key] || null;
      },
      replaceWith(saved) {
        reused.push({ id, saved });
      },
    }));
    const list = { querySelectorAll: () => rows };

    return {
      rows,
      querySelectorAll: () => rows,
      querySelector(selector) {
        return selector === ".resource-list" ? list : null;
      },
      contains() {
        return false;
      },
      replaceWith() {
        replacements++;
      },
    };
  }
  const feed = makeFeed(options.initialIds || [], options.initialFields || {});
  feed.contains = () => Boolean(options.focusInFeed);
  feed.querySelector = (selector) => {
    if (selector === ".resource-list") return { querySelectorAll: () => feed.rows };
    if (selector === "details[open]") return options.openDetails ? {} : null;

    return null;
  };

  let incomingFeed = makeFeed([]);
  const status = { textContent: "", dataset: {} };
  let applyClick;
  const apply = {
    hidden: true,
    textContent: "",
    addEventListener(name, listener) {
      if (name === "click") applyClick = listener;
    },
  };
  const root = {
    dataset: { beforeId: options.beforeId || "0" },
    querySelector(selector) {
      if (selector === `#${kind}-feed`) return feed;
      if (selector === `[data-${kind}-status]`) return status;
      if (selector === `[data-${kind}-apply]`) return apply;

      return null;
    },
  };
  const document = {
    activeElement: {},
    get hidden() {
      return hidden;
    },
    addEventListener(name, listener) {
      const handlers = listeners.get(name) || [];

      handlers.push(listener);
      listeners.set(name, handlers);
    },
    removeEventListener(name, listener) {
      listeners.set(
        name,
        (listeners.get(name) || []).filter((item) => item !== listener),
      );
    },
    querySelector(selector) {
      if (selector === `[data-${kind}-live]`) return activityVisible ? root : null;

      return null;
    },
    querySelectorAll() {
      return [];
    },
  };
  const navigations = [];
  const browserWindow = { addEventListener() {}, scrollY: 0 };
  const context = {
    document,
    window: browserWindow,
    location: {
      href: `http://homeharbor.test/admin/${kind}`,
      search: options.search || "",
      assign(path) {
        navigations.push(path);
      },
    },
    URL,
    URLSearchParams,
    AbortController,
    fetch(url, requestOptions) {
      requests.push({ url, options: requestOptions });
      return fetchImpl(url, requestOptions);
    },
    DOMParser: class {
      parseFromString() {
        return { querySelector: () => incomingFeed };
      }
    },
    setTimeout(callback, delay) {
      const id = ++nextTimer;

      timers.set(id, { callback, delay });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
  };

  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../static/live-poll.js"), "utf8") +
      "\n" +
      (kind === "connections"
        ? fs.readFileSync(path.join(__dirname, "../static/connections.js"), "utf8")
        : fs.readFileSync(path.join(__dirname, "../static/activity.js"), "utf8")),
    context,
  );
  return {
    listeners,
    timers,
    status,
    apply,
    feed,
    reused,
    requests,
    navigations,
    get replacements() {
      return replacements;
    },
    hide() {
      hidden = true;
      for (const listener of listeners.get("visibilitychange") || []) listener();
    },
    show() {
      hidden = false;
      for (const listener of listeners.get("visibilitychange") || []) listener();
    },
    navigateAway() {
      for (const listener of listeners.get("htmx:beforeSwap") || []) {
        listener({ detail: { target: { id: "admin-shell" }, shouldSwap: true } });
      }

      assert.equal(timers.size, 0);

      activityVisible = false;
      for (const listener of listeners.get("htmx:afterSwap") || []) {
        listener({ detail: { target: { id: "admin-shell" } } });
      }
    },
    restoreHistory(visible) {
      activityVisible = visible;

      const body = { tagName: "BODY" };
      for (const listener of listeners.get("htmx:afterSwap") || []) {
        listener({ target: body, detail: { target: body } });
      }

      for (const listener of listeners.get("htmx:historyRestore") || []) {
        listener({ target: body, detail: { cacheMiss: true } });
      }
    },
    rejectNavigation() {
      for (const listener of listeners.get("htmx:beforeSwap") || []) {
        listener({ detail: { target: { id: "admin-shell" }, shouldSwap: false } });
      }
    },
    readAt(scrollY) {
      browserWindow.scrollY = scrollY;
    },
    setReading({ focusInFeed = false, openDetails = false } = {}) {
      options.focusInFeed = focusInFeed;
      options.openDetails = openDetails;
    },
    setIncoming(ids, fields = {}) {
      incomingFeed = makeFeed(ids, fields);
    },
    applyPending() {
      applyClick();
    },
    fireTimer() {
      const [id, timer] = timers.entries().next().value;

      timers.delete(id);
      timer.callback();
    },
  };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test("activity schedules one four-second refresh and pauses in a hidden tab", () => {
  const page = activityPage();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [4000],
  );

  page.hide();

  assert.equal(page.timers.size, 0);
  assert.match(page.status.textContent, /paused/i);

  page.show();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [0],
  );

  page.navigateAway();

  assert.equal(page.timers.size, 0);
});

test("activity keeps one request in flight and retains old content on failure", async () => {
  let release;
  let calls = 0;
  const page = activityPage(
    () =>
      new Promise((resolve) => {
        calls++;
        release = resolve;
      }),
  );

  page.fireTimer();

  assert.equal(calls, 1);
  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [10000],
  );

  release({ ok: false, status: 503 });
  await flush();

  assert.equal(page.replacements, 0);
  assert.match(page.status.textContent, /stale/i);
  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [4000],
  );

  page.fireTimer();

  assert.equal(calls, 2);

  release({ ok: false, status: 503 });
  await flush();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [8000],
  );

  page.fireTimer();
  release({ ok: false, status: 503 });
  await flush();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [16000],
  );

  page.fireTimer();
  release({ ok: false, status: 503 });
  await flush();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [32000],
  );
});

test("activity polling follows body history restoration in both directions", () => {
  const page = activityPage();

  page.navigateAway();
  page.restoreHistory(true);

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [4000],
  );

  page.restoreHistory(false);

  assert.equal(page.timers.size, 0);
});

test("a rejected navigation keeps the visible activity poller running", () => {
  const page = activityPage();

  page.rejectNavigation();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [4000],
  );

  page.fireTimer();

  assert.equal(page.requests.length, 1);
});

test("applying pending activity keeps stale status until a successful refresh", async () => {
  let failed = false;
  const page = activityPage(
    async () =>
      failed
        ? { ok: false, status: 503 }
        : { ok: true, status: 200, text: async () => "<section id='activity-feed'>" },
    { initialIds: ["1"], openDetails: true },
  );

  page.setIncoming(["2", "1"]);
  page.fireTimer();
  await flush();

  assert.equal(page.apply.hidden, false);

  failed = true;
  page.fireTimer();
  await flush();

  assert.equal(page.status.dataset.state, "stale");

  page.applyPending();

  assert.equal(page.replacements, 1);
  assert.equal(page.status.dataset.state, "stale");

  failed = false;
  page.setReading();
  page.fireTimer();
  await flush();

  assert.equal(page.status.dataset.state, "live");
});

test("activity marks a hung request stale after ten seconds", async () => {
  const page = activityPage(
    (_url, options) =>
      new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () =>
          reject(Object.assign(new Error("deadline"), { name: "AbortError" })),
        );
      }),
  );

  page.fireTimer();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [10000],
  );

  page.fireTimer();
  await flush();

  assert.match(page.status.textContent, /stale/i);
  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [4000],
  );
});

test("activity redirects once when its session expires", async () => {
  const page = activityPage(async () => ({ ok: false, status: 401 }));

  page.fireTimer();
  await flush();

  assert.deepEqual(page.navigations, ["/admin/login"]);
  assert.equal(page.timers.size, 0);
});

test("activity resumes immediately when a hidden request is aborted", async () => {
  const page = activityPage(
    (_url, options) =>
      new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () =>
          reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
        );
      }),
  );

  page.fireTimer();
  page.hide();
  page.show();
  await flush();

  assert.deepEqual(
    [...page.timers.values()].map((timer) => timer.delay),
    [0],
  );
});

test("activity reuses stable rows and detects a lower-ID late commit", async () => {
  const page = activityPage(
    async () => ({ ok: true, status: 200, text: async () => "<section id='activity-feed'>" }),
    { initialIds: ["9", "7"] },
  );

  page.setIncoming(["9", "8", "7"]);
  page.readAt(240);
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.equal(page.apply.hidden, false);
  assert.match(page.apply.textContent, /1 new/);

  page.applyPending();

  assert.equal(page.replacements, 1);
  assert.equal(page.reused.length, 2);
  assert.equal(page.reused.find((item) => item.id === "7").saved, page.feed.rows[1]);
});

test("activity history counts only entries since its first recent window", async () => {
  const page = activityPage(
    async () => ({ ok: true, status: 200, text: async () => "<section id='activity-feed'>" }),
    { initialIds: ["5", "4"], beforeId: "5", search: "?before_id=5" },
  );

  page.setIncoming(["10", "9"]);
  page.fireTimer();
  await flush();

  assert.equal(page.apply.hidden, true);

  page.setIncoming(["11", "10"]);
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.match(page.apply.textContent, /1 new/);
});

test("activity retains filters and holds a focused or expanded feed in place", async () => {
  const page = activityPage(
    async () => ({ ok: true, status: 200, text: async () => "<section id='activity-feed'>" }),
    { initialIds: ["5"], search: "?action=device.revoked&target_id=client-1&limit=25" },
  );

  page.setIncoming(["6", "5"]);
  page.setReading({ focusInFeed: true });
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.equal(page.apply.hidden, false);
  assert.equal(
    page.requests[0].url,
    "/admin/activity/fragment?action=device.revoked&target_id=client-1&limit=25",
  );
  assert.equal(page.requests[0].options.cache, "no-store");

  page.setReading({ openDetails: true });
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);

  page.setReading();
  page.applyPending();

  assert.equal(page.replacements, 1);
});

test("recovery enables secret entry only after intercepting submission", () => {
  let submit;
  const fieldset = {
    set disabled(value) {
      assert.equal(typeof submit, "function");
      assert.equal(value, false);
    },
  };
  const recovery = {
    addEventListener(name, listener) {
      assert.equal(name, "submit");

      submit = listener;
    },
    querySelector(selector) {
      assert.equal(selector, "fieldset");

      return fieldset;
    },
  };

  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/auth-ui.js"), "utf8"), {
    document: {
      querySelector(selector) {
        return selector === "#recovery" ? recovery : null;
      },
    },
    window: { addEventListener() {} },
  });

  assert.equal(typeof submit, "function");
});

for (const code of [
  "bootstrap_recovery_unavailable",
  "bootstrap_session_unavailable",
  "unrecognized",
]) {
  test(`${code} announces incomplete setup without enabling blind retry`, async () => {
    const status = { textContent: "", classList: { toggle() {} } };
    const codes = { hidden: true, textContent: "" };
    const button = { disabled: false, hidden: false, setAttribute() {}, removeAttribute() {} };
    const context = vm.createContext({
      document: {
        querySelector(selector) {
          return selector === "#status"
            ? status
            : selector === "#codes-value" || selector === "#recovery-codes"
              ? codes
              : null;
        },
      },
      window: { addEventListener() {} },
      AbortController,
      setTimeout,
      clearTimeout,
      fetch: async () => ({
        ok: false,
        status: 503,
        json: async () => ({ code, error: "opaque" }),
      }),
      button,
    });

    vm.runInContext(fs.readFileSync(path.join(__dirname, "../static/auth-ui.js"), "utf8"), context);
    await vm.runInContext('runAuth(button, () => authRequest("bootstrap/finish", {}))', context);
    if (code === "unrecognized") {
      assert.equal(status.textContent, "Sign-in is temporarily unavailable. Try again shortly.");
      assert.equal(button.hidden, false);
    } else {
      assert.match(status.textContent, /passkey.*saved/i);
      assert.match(status.textContent, /reload.*sign in/i);
      assert.equal(button.hidden, true);
    }

    assert.equal(codes.hidden, true);
    assert.equal(codes.textContent, "");
  });
}

test("connections refresh pauses while hidden and expires the session once", async () => {
  const page = activityPage(async () => ({ status: 401, ok: false }), {
    kind: "connections",
    search: "?device_id=phone",
  });

  assert.equal(page.timers.size, 1);

  page.hide();

  assert.equal(page.timers.size, 0);

  page.show();
  page.fireTimer();
  await flush();

  assert.deepEqual(page.navigations, ["/admin/login"]);
  assert.equal(page.timers.size, 0);
  assert.equal(page.requests[0].url, "/admin/connections/fragment?device_id=phone");
});

test("connections abort an in-flight refresh when leaving the page", async () => {
  const page = activityPage(
    (_url, options) =>
      new Promise((_resolve, reject) =>
        options.signal.addEventListener("abort", () =>
          reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
        ),
      ),
    { kind: "connections" },
  );

  page.fireTimer();
  await flush();

  assert.equal(page.requests.length, 1);

  page.navigateAway();
  await flush();

  assert.equal(page.requests[0].options.signal.aborted, true);
  assert.equal(page.timers.size, 0);
  assert.equal(page.replacements, 0);
});

test("connections update stale state without replacing a focused report", async () => {
  const key = "phone/phone";
  const page = activityPage(async () => ({ status: 200, ok: true, text: async () => "" }), {
    kind: "connections",
    focusInFeed: true,
    initialIds: [key],
    initialFields: { [key]: { state: "Runtime running", freshness: "Recent report" } },
  });

  page.setIncoming([key], {
    [key]: { state: "State unknown", freshness: "Stale report · current state unknown" },
  });
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.equal(page.feed.rows[0].fieldNodes.state.textContent, "State unknown");
  assert.match(page.feed.rows[0].fieldNodes.freshness.textContent, /Stale/);
  assert.equal(page.apply.hidden, true);
});

test("connections mark withdrawn peer reports unknown while preserving open details", async () => {
  const key = "gateway/phone";
  const page = activityPage(async () => ({ status: 200, ok: true, text: async () => "" }), {
    kind: "connections",
    openDetails: true,
    initialIds: [key],
    initialFields: { [key]: { state: "Reporter: Runtime running", freshness: "Recent report" } },
  });

  page.setIncoming([]);
  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.equal(page.feed.rows[0].fieldNodes.state.textContent, "State unknown");
  assert.match(page.feed.rows[0].fieldNodes.freshness.textContent, /not in latest view/);
  assert.equal(page.apply.hidden, false);
});

test("connections stop presenting current running state when refresh fails", async () => {
  const key = "phone/phone";
  const page = activityPage(async () => ({ status: 503, ok: false }), {
    kind: "connections",
    initialIds: [key],
    initialFields: { [key]: { state: "Runtime running", freshness: "Recent report" } },
  });

  page.fireTimer();
  await flush();

  assert.equal(page.replacements, 0);
  assert.equal(page.feed.rows[0].fieldNodes.state.textContent, "State unknown");
  assert.match(page.feed.rows[0].fieldNodes.freshness.textContent, /could not be refreshed/);
  assert.equal(page.status.dataset.state, "stale");
});

function passwordPage(pathname, response) {
  const listeners = new Map();
  const events = new Map();
  const requests = [];
  const navigations = [];
  const fields = {
    email: { value: "owner@example.test" },
    code: { value: "279037" },
    password: { value: " private long password " },
    _csrf: { value: "bound-csrf" },
  };
  const button = { disabled: false, setAttribute() {}, removeAttribute() {} };
  const fieldset = { disabled: true };
  const status = { textContent: "", classList: { toggle() {} } };
  const form = {
    elements: {
      namedItem(name) {
        return fields[name] || null;
      },
    },
    addEventListener(name, callback) {
      listeners.set(name, callback);
    },
    querySelector(selector) {
      return selector === "fieldset" ? fieldset : selector.includes("button") ? button : null;
    },
  };

  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/auth-ui.js"), "utf8"), {
    document: {
      querySelector(selector) {
        return selector === pathname ? form : selector === "#status" ? status : null;
      },
    },
    window: {
      addEventListener(name, callback) {
        events.set(name, callback);
      },
    },
    location: {
      replace(value) {
        navigations.push(value);
      },
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return response;
    },
    AbortController,
    setTimeout,
    clearTimeout,
  });
  return { listeners, events, requests, navigations, fields, fieldset, status, form };
}

test("password login intercepts secret entry, preserves password bytes and advances only to MFA", async () => {
  const page = passwordPage("#password-login", {
    ok: true,
    status: 200,
    json: async () => ({ next: "second_factor" }),
  });

  assert.equal(typeof page.listeners.get("submit"), "function");
  assert.equal(page.fieldset.disabled, false);

  await page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  assert.equal(page.requests.length, 1);
  assert.equal(page.requests[0].url, "/api/v1/auth/password");
  assert.equal(JSON.parse(page.requests[0].options.body).password, " private long password ");
  assert.equal(page.fields.password.value, "");
  assert.deepEqual(page.navigations, ["/admin/login"]);
});

test("failed password stays on the current step and clears private fields", async () => {
  const page = passwordPage("#password-login", {
    ok: false,
    status: 401,
    json: async () => ({ error: "PRIVATE_SERVER_DIAGNOSTIC" }),
  });

  await page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  assert.deepEqual(page.navigations, []);
  assert.equal(page.fields.password.value, "");
  assert.doesNotMatch(page.status.textContent, /PRIVATE_SERVER_DIAGNOSTIC/);

  page.fields.password.value = "unsent secret";
  page.events.get("pagehide")();

  assert.equal(page.fields.password.value, "");
});

test("owner setup submits its scoped CSRF proof and returns to password sign-in", async () => {
  const page = passwordPage("#owner-password", { ok: true, status: 204 });

  await page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  assert.equal(page.requests[0].url, "/api/v1/auth/owner/password");
  assert.equal(page.requests[0].options.headers["X-CSRF-Token"], "bound-csrf");
  assert.equal(page.fields.password.value, "");
  assert.deepEqual(page.navigations, ["/admin/login"]);
});

function securityPage(fetchImpl, credentialImpl) {
  const events = new Map();
  const windowEvents = new Map();
  const requests = [];
  const navigations = [];
  const seed = { textContent: "", hidden: true };
  const codes = { textContent: "", hidden: true };
  const status = { textContent: "", classList: { toggle() {} }, focus() {} };
  const button = {
    disabled: false,
    hidden: false,
    textContent: "Continue",
    setAttribute() {},
    removeAttribute() {},
  };
  const fields = {
    code: { value: "123456" },
    name: { value: "MacBook" },
    id: { value: "owned-key" },
  };
  const fieldset = { disabled: true };
  const root = {
    dataset: { csrf: "personal-csrf", recent: "true" },
    querySelector(selector) {
      if (selector === "[data-security-status]") return status;
      if (["[data-totp-secret]", "[data-totp-enrollment]"].includes(selector)) return seed;
      if (["[data-recovery-values]", "[data-security-codes]"].includes(selector)) return codes;

      return null;
    },
    querySelectorAll(selector) {
      return selector === "fieldset" ? [fieldset] : [fields.code];
    },
    contains() {
      return true;
    },
  };
  let signals = 0;

  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/security.js"), "utf8"), {
    document: {
      querySelector(selector) {
        return selector === "[data-account-security]" ? root : null;
      },
      addEventListener(name, callback) {
        events.set(name, callback);
      },
    },
    window: {
      PublicKeyCredential: {
        signalUnknownCredential() {
          signals++;
        },
        signalAllAcceptedCredentials() {
          signals++;
        },
      },
      addEventListener(name, callback) {
        windowEvents.set(name, callback);
      },
    },
    navigator: { credentials: { create: credentialImpl } },
    location: {
      replace(value) {
        navigations.push(value);
      },
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return fetchImpl(url, options);
    },
    AbortController,
    setTimeout,
    clearTimeout,
    atob,
    btoa,
    Uint8Array,
    TypeError,
  });

  const submit = async (action) => {
    const form = {
      dataset: { securityAction: action },
      elements: {
        namedItem(name) {
          return fields[name];
        },
      },
      closest(selector) {
        return selector === "[data-account-security]" ? root : this;
      },
      querySelector() {
        return button;
      },
      matches(selector) {
        return selector === "[data-security-action]";
      },
    };

    await events.get("submit")({ target: form, preventDefault() {} });
  };

  return {
    events,
    windowEvents,
    requests,
    navigations,
    seed,
    codes,
    status,
    button,
    fields,
    fieldset,
    root,
    submit,
    signals: () => signals,
  };
}

test("security recovery generation uses CSRF and wipes secrets on departure", async () => {
  const page = securityPage(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ codes: ["private-code"] }),
  }));

  assert.equal(page.fieldset.disabled, false);

  await page.submit("recovery-codes");

  assert.equal(page.requests.length, 1);
  assert.equal(page.requests[0].url, "/api/v1/admin/account/recovery-codes");
  assert.equal(page.requests[0].options.headers["X-CSRF-Token"], "personal-csrf");
  assert.equal(page.codes.textContent, "private-code");
  assert.equal(page.codes.hidden, false);

  page.seed.textContent = "private-seed";
  page.windowEvents.get("pagehide")();

  assert.equal(page.codes.textContent, "");
  assert.equal(page.seed.textContent, "");
  assert.equal(page.fields.code.value, "");
});

test("security ignores an in-flight secret response after HTMX departure", async () => {
  let deliver;
  const page = securityPage(
    () =>
      new Promise((resolve) => {
        deliver = resolve;
      }),
  );
  const pending = page.submit("recovery-codes");

  page.events.get("htmx:beforeSwap")({ detail: { target: { id: "admin-shell" } } });
  deliver({ ok: true, status: 200, json: async () => ({ codes: ["late-private-code"] }) });
  await pending;

  assert.equal(page.codes.textContent, "");
  assert.equal(page.codes.hidden, true);
  assert.deepEqual(page.navigations, []);
});

test("security never deletes provider passkeys or retries after an ambiguous save", async () => {
  const credential = {
    id: "key",
    type: "public-key",
    rawId: new Uint8Array([1]),
    response: { attestationObject: new Uint8Array([2]), clientDataJSON: new Uint8Array([3]) },
  };
  const page = securityPage(
    async (url) =>
      url.endsWith("/begin")
        ? {
            ok: true,
            status: 200,
            json: async () => ({
              ceremony_id: "one-use",
              options: { publicKey: { challenge: "AQ", user: { id: "Ag" } } },
            }),
          }
        : { ok: false, status: 503 },
    async () => credential,
  );

  await page.submit("passkeys/add");

  assert.equal(page.requests.length, 2);
  assert.equal(page.signals(), 0);
  assert.deepEqual(page.navigations, []);
  assert.match(page.status.textContent, /reload.*review/i);
  assert.equal(page.button.disabled, true);
});

test("second factor code reaches admin only after server verification", async () => {
  const page = passwordPage("#factor-code", { ok: true, status: 204 });

  await page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  assert.equal(page.requests[0].url, "/api/v1/auth/factor");
  assert.equal(JSON.parse(page.requests[0].options.body).method, "totp");
  assert.equal(page.fields.code.value, "");
  assert.deepEqual(page.navigations, ["/admin/"]);
});
test("second factor recovery remains password-bound and clears its input", async () => {
  const page = passwordPage("#factor-recovery", { ok: false, status: 401, json: async () => ({}) });

  assert.equal(typeof page.listeners.get("submit"), "function");

  await page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  assert.equal(page.requests[0].url, "/api/v1/auth/factor");
  assert.equal(JSON.parse(page.requests[0].options.body).method, "recovery");
  assert.equal(page.fields.code.value, "");
  assert.deepEqual(page.navigations, []);

  page.fields.code.value = "unsent-recovery";
  page.events.get("pagehide")();

  assert.equal(page.fields.code.value, "");
});

test("password response cannot navigate after leaving sign-in", async () => {
  let deliver;
  const page = passwordPage(
    "#password-login",
    new Promise((resolve) => {
      deliver = resolve;
    }),
  );
  const pending = page.listeners.get("submit")({ preventDefault() {}, currentTarget: page.form });

  page.events.get("pagehide")();
  deliver({ ok: true, status: 200, json: async () => ({ next: "second_factor" }) });
  await pending;

  assert.deepEqual(page.navigations, []);
});

test("security never renders private successful-response parse diagnostics", async () => {
  const page = securityPage(async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new SyntaxError("PRIVATE_RECOVERY_CODE in JSON response");
    },
  }));

  await page.submit("recovery-codes");

  assert.doesNotMatch(page.status.textContent, /PRIVATE_RECOVERY_CODE/);
  assert.equal(page.codes.textContent, "");
  assert.match(page.status.textContent, /Reload/);
});

test("email confirmation request keeps the current security session", async () => {
  const page = securityPage(async () => ({ ok: true, status: 204 }));

  await page.submit("email/verification");

  assert.equal(page.requests[0].url, "/api/v1/admin/account/email/verification");
  assert.deepEqual(page.navigations, []);
  assert.match(page.status.textContent, /confirmation.*queued/i);
});
