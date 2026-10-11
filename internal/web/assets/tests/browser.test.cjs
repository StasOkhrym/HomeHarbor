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
      querySelectorAll() {
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
  return { listeners, navigations, status, heading, navigation };
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

function activityPage(fetchImpl = async () => ({ ok: false, status: 503 }), options = {}) {
  const listeners = new Map();
  const timers = new Map();
  let nextTimer = 0;
  let activityVisible = true;
  let hidden = false;
  let replacements = 0;
  const reused = [];
  function makeFeed(ids) {
    const rows = ids.map((id) => ({
      dataset: { recordId: id },
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
  const feed = makeFeed(options.initialIds || []);
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
      if (selector === "#activity-feed") return feed;
      if (selector === "[data-activity-status]") return status;
      if (selector === "[data-activity-apply]") return apply;
      return null;
    },
  };
  const document = {
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
      if (selector === "[data-activity-live]") return activityVisible ? root : null;
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
      href: "http://homeharbor.test/admin/activity",
      search: options.search || "",
      assign(path) {
        navigations.push(path);
      },
    },
    URL,
    URLSearchParams,
    AbortController,
    fetch: fetchImpl,
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
    fs.readFileSync(path.join(__dirname, "../static/activity.js"), "utf8"),
    context,
  );
  return {
    listeners,
    timers,
    status,
    apply,
    feed,
    reused,
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
        listener({ detail: { target: { id: "admin-shell" } } });
      }
      assert.equal(timers.size, 0);
      activityVisible = false;
      for (const listener of listeners.get("htmx:afterSwap") || []) {
        listener({ detail: { target: { id: "admin-shell" } } });
      }
    },
    readAt(scrollY) {
      browserWindow.scrollY = scrollY;
    },
    setIncoming(ids) {
      incomingFeed = makeFeed(ids);
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
