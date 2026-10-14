"use strict";

let activeActivityPoller = null;
let lastActivityWindow = null;

function syncActivityPoller() {
  activeActivityPoller?.stop();
  activeActivityPoller = null;
  const root = document.querySelector("[data-activity-live]");
  if (!root) return;
  activeActivityPoller = new ActivityPoller(root);
  activeActivityPoller.start();
}

class ActivityPoller {
  constructor(root) {
    this.root = root;
    this.feed = root.querySelector("#activity-feed");
    this.status = root.querySelector("[data-activity-status]");
    this.applyButton = root.querySelector("[data-activity-apply]");
    const query = new URLSearchParams(location.search);
    this.history = query.has("before_id") || root.dataset.beforeId !== "0";
    query.delete("before_id");
    if (!query.has("limit")) query.set("limit", "100");
    this.queryKey = query.toString();
    this.fragmentURL = `/admin/activity/fragment?${this.queryKey}`;
    this.liveURL = `/admin/activity?${this.queryKey}`;
    this.seen =
      this.history && lastActivityWindow?.key === this.queryKey
        ? new Set(lastActivityWindow.ids)
        : this.history
          ? null
          : this.recordIDs(this.feed);
    this.pendingIDs = new Set();
    this.pendingFeed = null;
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
    this.onApply = () => this.applyPending();
  }

  recordIDs(feed) {
    return new Set(
      [...feed.querySelectorAll("li[data-record-id]")].map((row) => row.dataset.recordId),
    );
  }

  start() {
    this.active = true;
    document.addEventListener("visibilitychange", this.onVisibility);
    this.applyButton.addEventListener("click", this.onApply);
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
    this.applyButton.removeEventListener?.("click", this.onApply);
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
    this.setStatus("Live · checking for new activity", "live");
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
      if (!response.ok) throw new Error("activity request failed");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      if (!this.active || document.hidden) return;
      const incoming = page.querySelector("#activity-feed");
      if (!incoming) throw new Error("activity fragment missing");
      this.failures = 0;
      this.accept(incoming);
    } catch (error) {
      if (this.active && !document.hidden && (error.name !== "AbortError" || this.timedOut)) {
        this.failures += 1;
        this.setStatus("Stale · latest activity could not be loaded", "stale");
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

  accept(incoming) {
    const ids = this.recordIDs(incoming);
    if (this.seen === null) {
      // Direct links into older history have no baseline for a truthful new count.
      this.seen = ids;
    } else {
      for (const id of ids) if (!this.seen.has(id)) this.pendingIDs.add(id);

      this.seen = ids;
    }

    lastActivityWindow = { key: this.queryKey, ids };
    if (this.history || this.isReading()) {
      this.pendingFeed = incoming;
      this.updatePendingStatus();
      return;
    }

    this.reconcile(incoming);
    this.pendingFeed = null;
    this.pendingIDs.clear();
    this.applyButton.hidden = true;
    this.setStatus("Live · activity is current", "live");
  }

  isReading() {
    return (
      window.scrollY > 160 ||
      this.feed.contains(document.activeElement) ||
      Boolean(this.feed.querySelector("details[open]"))
    );
  }

  updatePendingStatus() {
    const count = this.pendingIDs.size;
    if (count) {
      this.applyButton.hidden = false;
      this.applyButton.textContent = this.history
        ? `${count} new · return to recent activity`
        : `Show ${count} new event${count === 1 ? "" : "s"}`;
      this.setStatus(`${count} new event${count === 1 ? "" : "s"} · view held in place`, "paused");
    } else {
      this.setStatus(
        this.history
          ? "Viewing older activity · live checks continue"
          : "Live · activity is current",
        "live",
      );
    }
  }

  reconcile(incoming) {
    const currentList = this.feed.querySelector(".resource-list");
    const incomingList = incoming.querySelector(".resource-list");
    if (currentList && incomingList) {
      const existing = new Map(
        [...currentList.querySelectorAll("li[data-record-id]")].map((row) => [
          row.dataset.recordId,
          row,
        ]),
      );
      for (const row of [...incomingList.querySelectorAll("li[data-record-id]")]) {
        const saved = existing.get(row.dataset.recordId);
        if (saved) row.replaceWith(saved);
      }
    }

    this.feed.replaceWith(incoming);
    this.feed = incoming;
  }

  applyPending() {
    if (this.history) {
      location.assign(this.liveURL);
      return;
    }
    if (!this.pendingFeed) return;

    this.reconcile(this.pendingFeed);
    this.pendingFeed = null;
    this.pendingIDs.clear();
    this.applyButton.hidden = true;
    if (this.failures) {
      this.setStatus("Stale · latest activity could not be loaded", "stale");
    } else {
      this.setStatus("Live · activity is current", "live");
    }
  }

  setStatus(message, state) {
    if (this.status.textContent !== message) this.status.textContent = message;
    this.status.dataset.state = state;
    this.root.dataset.state = state;
  }
}

syncActivityPoller();

document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail?.shouldSwap === false) return;
  if (event.detail?.target?.id === "admin-shell" || event.target?.id === "admin-shell") {
    activeActivityPoller?.stop();
  }
});

document.addEventListener("htmx:afterSwap", (event) => {
  if (event.detail?.target?.id === "admin-shell" || event.target?.id === "admin-shell") {
    syncActivityPoller();
  }
});

document.addEventListener("htmx:historyRestore", syncActivityPoller);

window.addEventListener("pagehide", () => activeActivityPoller?.stop());
