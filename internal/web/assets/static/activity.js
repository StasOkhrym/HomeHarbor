"use strict";

let lastActivityWindow = null;

class ActivityPoller extends window.HomeHarborLivePoller {
  constructor(root) {
    super(root, {
      status: root.querySelector("[data-activity-status]"),
      fragmentSelector: "#activity-feed",
      checkingMessage: "Live · checking for new activity",
      staleMessage: "Stale · latest activity could not be loaded",
    });
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
    this.onApply = () => this.applyPending();
  }

  start() {
    this.applyButton.addEventListener("click", this.onApply);
    super.start();
  }

  stop() {
    this.applyButton.removeEventListener?.("click", this.onApply);
    super.stop();
  }

  recordIDs(feed) {
    return new Set(
      [...feed.querySelectorAll("li[data-record-id]")].map((row) => row.dataset.recordId),
    );
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
}

window.HomeHarborLivePoller.mount("[data-activity-live]", (root) => new ActivityPoller(root));
