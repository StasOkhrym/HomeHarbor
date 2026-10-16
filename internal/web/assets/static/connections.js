"use strict";

class ConnectionsPoller extends window.HomeHarborLivePoller {
  constructor(root) {
    super(root, {
      status: root.querySelector("[data-connections-status]"),
      fragmentSelector: "#connections-feed",
      checkingMessage: "Live · checking runtime reports",
      staleMessage: "Stale · runtime reports could not be loaded",
    });
    this.feed = root.querySelector("#connections-feed");
    this.applyButton = root.querySelector("[data-connections-apply]");
    this.fragmentURL = `/admin/connections/fragment?${new URLSearchParams(location.search)}`;
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

  setStatus(message, state) {
    super.setStatus(message, state);
    if (state === "stale" || (state === "paused" && document.hidden)) {
      for (const row of this.feed.querySelectorAll("li[data-connection-key]")) {
        this.markUnknown(
          row,
          state === "stale"
            ? "Reports could not be refreshed · current state unknown"
            : "Refresh paused · current state unknown",
        );
      }
    }
  }

  markUnknown(row, message) {
    const state = row.querySelector('[data-report-field="state"]');
    if (state) {
      state.textContent = "State unknown";
      state.dataset.state = "unknown";
    }

    const freshness = row.querySelector('[data-report-field="freshness"]');
    if (freshness) freshness.textContent = message;
  }

  isReading() {
    return (
      window.scrollY > 160 ||
      this.feed.contains(document.activeElement) ||
      Boolean(this.feed.querySelector("details[open]"))
    );
  }

  accept(incoming) {
    if (this.isReading()) {
      const changed = this.patchVisibleReports(incoming);
      this.pendingFeed = changed ? incoming : null;
      this.applyButton.hidden = !changed;
      this.setStatus(
        changed
          ? "New reports available · current rows refreshed"
          : "Live · runtime reports are current",
        changed ? "paused" : "live",
      );
      return;
    }

    this.replace(incoming);
  }

  patchVisibleReports(incoming) {
    const incomingRows = new Map(
      [...incoming.querySelectorAll("li[data-connection-key]")].map((row) => [
        row.dataset.connectionKey,
        row,
      ]),
    );
    const currentRows = [...this.feed.querySelectorAll("li[data-connection-key]")];
    let changed = currentRows.length !== incomingRows.size;
    for (const current of currentRows) {
      const next = incomingRows.get(current.dataset.connectionKey);
      if (!next) {
        changed = true;
        this.markUnknown(current, "Previous report · not in latest view");
        continue;
      }

      for (const value of next.querySelectorAll("[data-report-field]")) {
        const target = current.querySelector(`[data-report-field="${value.dataset.reportField}"]`);
        if (!target) {
          changed = true;
          continue;
        }

        // Keep summary/focus nodes; replace only public, noninteractive value
        // children, including semantic time/code nodes from the server template.
        target.replaceChildren(...[...value.childNodes].map((node) => node.cloneNode(true)));
        if (value.dataset.state !== undefined) target.dataset.state = value.dataset.state;
      }
    }

    return changed;
  }

  replace(incoming) {
    this.feed.replaceWith(incoming);
    this.feed = incoming;
    this.pendingFeed = null;
    this.applyButton.hidden = true;
    this.setStatus("Live · runtime reports are current", "live");
  }

  applyPending() {
    if (!this.pendingFeed) return;

    this.replace(this.pendingFeed);
    if (this.failures) this.setStatus(this.staleMessage, "stale");
    this.feed.querySelector("h2")?.focus?.();
  }
}

window.HomeHarborLivePoller.mount("[data-connections-live]", (root) => new ConnectionsPoller(root));
