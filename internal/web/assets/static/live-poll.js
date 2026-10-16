"use strict";

// Shared transport owns visibility, cancellation, timeouts and session expiry.
// Each view owns how its data changes without disturbing the reader.
window.HomeHarborLivePoller = class LiveFragmentPoller {
  constructor(root, { status, fragmentSelector, checkingMessage, staleMessage }) {
    this.root = root;
    this.status = status;
    this.fragmentSelector = fragmentSelector;
    this.checkingMessage = checkingMessage;
    this.staleMessage = staleMessage;
    this.timer = null;
    this.requestTimer = null;
    this.controller = null;
    this.inflight = false;
    this.active = false;
    this.failures = 0;
    this.redirected = false;
    this.resumeNow = false;
    this.timedOut = false;
    this.onVisibility = () => this.visibilityChanged();
  }

  static mount(selector, create) {
    let active = null;
    const sync = () => {
      active?.stop();
      active = null;

      const root = document.querySelector(selector);
      if (root) {
        active = create(root);
        active.start();
      }
    };
    const shell = (event) =>
      event.detail?.target?.id === "admin-shell" || event.target?.id === "admin-shell";
    sync();
    document.addEventListener("htmx:beforeSwap", (event) => {
      if (event.detail?.shouldSwap !== false && shell(event)) active?.stop();
    });
    document.addEventListener("htmx:afterSwap", (event) => {
      if (shell(event)) sync();
    });
    document.addEventListener("htmx:historyRestore", sync);
    window.addEventListener("pagehide", () => active?.stop());
  }

  start() {
    this.active = true;
    document.addEventListener("visibilitychange", this.onVisibility);
    if (document.hidden) this.setStatus("Paused · tab is hidden", "paused");
    else {
      this.setStatus("Live · checking every 4 seconds", "live");
      this.schedule(4000);
    }
  }

  stop() {
    this.active = false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    if (this.requestTimer !== null) clearTimeout(this.requestTimer);
    this.requestTimer = null;
    this.controller?.abort();
    document.removeEventListener("visibilitychange", this.onVisibility);
  }

  schedule(delay) {
    if (!this.active || document.hidden || this.timer !== null || this.inflight) return;

    this.timer = setTimeout(() => {
      this.timer = null;
      void this.refresh();
    }, delay);
  }

  visibilityChanged() {
    if (document.hidden) {
      if (this.timer !== null) clearTimeout(this.timer);
      this.timer = null;
      this.controller?.abort();
      this.setStatus("Paused · tab is hidden", "paused");
      return;
    }

    this.setStatus(this.checkingMessage, "live");
    if (this.inflight) this.resumeNow = true;
    else this.schedule(0);
  }

  async refresh() {
    if (!this.active || document.hidden || this.inflight) return;

    this.inflight = true;
    this.controller = new AbortController();
    this.timedOut = false;
    this.requestTimer = setTimeout(() => {
      this.timedOut = true;
      this.controller?.abort();
    }, 10000);

    try {
      const response = await fetch(this.fragmentURL, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { "HX-Request": "true" },
        signal: this.controller.signal,
      });
      if (!this.active || document.hidden) return;
      if (response.status === 401) {
        if (!this.redirected) {
          this.redirected = true;
          this.stop();
          location.assign("/admin/login");
        }

        return;
      }
      if (!response.ok) throw new Error("live fragment request failed");

      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      if (!this.active || document.hidden) return;

      const incoming = page.querySelector(this.fragmentSelector);
      if (!incoming) throw new Error("live fragment missing");

      this.failures = 0;
      this.accept(incoming);
    } catch (error) {
      if (this.active && !document.hidden && (error.name !== "AbortError" || this.timedOut)) {
        this.failures += 1;
        this.setStatus(this.staleMessage, "stale");
      }
    } finally {
      if (this.requestTimer !== null) clearTimeout(this.requestTimer);
      this.requestTimer = null;
      this.inflight = false;
      this.controller = null;
      if (this.active && !document.hidden) {
        const delay = this.resumeNow
          ? 0
          : this.failures
            ? Math.min(4000 * 2 ** (this.failures - 1), 32000)
            : 4000;
        this.resumeNow = false;
        this.schedule(delay);
      }
    }
  }

  setStatus(message, state) {
    if (this.status.textContent !== message) this.status.textContent = message;
    this.status.dataset.state = state;
    this.root.dataset.state = state;
  }
};
