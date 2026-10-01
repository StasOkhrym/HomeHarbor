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
  const context = {
    document: {
      addEventListener(name, listener) {
        listeners.set(name, listener);
      },
      querySelector(selector) {
        return selector === "#browser-status" ? status : null;
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
  return { listeners, navigations, status };
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
