/*
 * ZeroLeak
 * Copyright (C) 2026 Winn Htut Hein
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// UI side of things: editors, scroll sync, rendering, event wiring.
// (the actual scanning lives in the first script block / engine.js)
(() => {
  "use strict";

  const { scan, IdentityRegistry, LIMITS, countLines, byteLength, formatBytes } = globalThis.ZeroLeakEngine;
  const nextFrame = () => new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve)));
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // Past this size the output is shown as one plain text node. Thousands of
  // highlight elements are fine; hundreds of thousands are not.
  const HIGHLIGHT_MAX = 400_000;

  const $ = (id) => document.getElementById(id);
  const ui = {
    source: $("code-in"), output: $("result-box"), srcMeta: $("in-info"), outMeta: $("out-info"),
    ledger: $("hit-list"), ledgerCount: $("hit-count"), idList: $("alias-list"), idCount: $("alias-count"),
    watchlist: $("name-list"), threshold: $("ent-thresh"), minLen: $("min-chars"),
    thresholdOut: $("ent-thresh-val"), minLenOut: $("min-chars-val"),
    backdrop: $("hl-layer"), legend: $("hl-key"),
    seal: $("safe-badge"), sealDetail: $("badge-note"),
    statusMain: $("foot-msg"), statusTime: $("foot-ms"), toast: $("popup")
  };

  const state = { tab: "code", result: null, registry: new IdentityRegistry(), ticket: 0, blocked: 0 };

  // The gutter's inner column moves with a transform, so scrolling never
  // triggers layout. Numbers are rebuilt only when the line count changes.
  class Gutter {
    constructor(el) {
      this.inner = document.createElement("div");
      el.append(this.inner);
      this.lines = 0;
      this.setLines(1);
    }
    setLines(n) {
      n = Math.max(n, 1);
      if (n === this.lines) return;
      this.lines = n;
      this.inner.textContent = Array.from({ length: n }, (_, i) => i + 1).join("\n");
    }
    scrollTo(y) { this.inner.style.transform = `translate3d(0, ${-y}px, 0)`; }
  }

  const gutters = new Map([
    [ui.source, new Gutter($("line-nums-in"))],
    [ui.output, new Gutter($("line-nums-out"))]
  ]);

  // Writing scrollTop on one pane makes the browser fire a scroll event on it,
  // which would bounce back. A timed lock can swallow real events, so instead we
  // remember the exact position we wrote and ignore only the event reporting it.
  // The prompt tab is a different document, so it doesn't sync.
  const echoes = new WeakMap();
  const pendingPaint = new Set();

  const moveBackdrop = () => {
    ui.backdrop.style.transform = `translate3d(${-ui.source.scrollLeft}px, ${-ui.source.scrollTop}px, 0)`;
  };

  function schedulePaint(pane) {
    if (!pendingPaint.size) {
      requestAnimationFrame(() => {
        pendingPaint.forEach((p) => gutters.get(p).scrollTo(p.scrollTop));
        if (pendingPaint.has(ui.source)) moveBackdrop();
        pendingPaint.clear();
      });
    }
    pendingPaint.add(pane);
  }

  function follow(from, to) {
    const echo = echoes.get(from);
    echoes.delete(from);
    if (echo && echo.top === from.scrollTop && echo.left === from.scrollLeft) return;
    if (state.tab !== "code") return;

    const fromRange = from.scrollHeight - from.clientHeight;
    const toRange = to.scrollHeight - to.clientHeight;
    const top = fromRange > 0 ? (from.scrollTop / fromRange) * toRange : 0;
    if (Math.abs(to.scrollTop - top) < 1 && to.scrollLeft === from.scrollLeft) return;

    to.scrollTop = top;
    to.scrollLeft = from.scrollLeft;
    echoes.set(to, { top: to.scrollTop, left: to.scrollLeft }); // read back, the browser may clamp
  }

  for (const [a, b] of [[ui.source, ui.output], [ui.output, ui.source]]) {
    a.addEventListener("scroll", () => { schedulePaint(a); follow(a, b); }, { passive: true });
  }

  // The CSP in index.html is what actually stops requests; the browser refuses
  // them before any script runs. All this does is count the refusals it reports.
  function setSeal(mode) {
    const label = state.blocked
      ? `${state.blocked} request${state.blocked === 1 ? "" : "s"} blocked`
      : "0 requests sent";
    ui.seal.dataset.state = mode === "working" ? "working" : state.blocked ? "alert" : "sealed";
    ui.sealDetail.textContent = mode === "working" ? "Scanning in memory, network is off" : `Lives in this tab only, ${label}`;
  }

  document.addEventListener("securitypolicyviolation", () => { state.blocked++; setSeal(); });

  let toastTimer = 0;
  function toast(message) {
    ui.toast.textContent = message;
    ui.toast.classList.add("on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => ui.toast.classList.remove("on"), 3200);
  }

  const status = (message, ms) => {
    ui.statusMain.textContent = message;
    ui.statusTime.textContent = ms == null ? "" : `${ms.toFixed(1)} ms`;
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderSourceMeta() {
    const text = ui.source.value;
    gutters.get(ui.source).setLines(countLines(text));
    ui.srcMeta.textContent = text ? `${countLines(text).toLocaleString()} lines, ${formatBytes(byteLength(text))}` : "Nothing yet";
  }

  // Marks go stale the moment the text changes, so drop them until the next scan.
  function paintSource(text, marks) {
    if (!marks || !marks.length || text.length > HIGHLIGHT_MAX) { ui.backdrop.replaceChildren(); ui.legend.hidden = true; return; }
    const frag = document.createDocumentFragment();
    let last = 0;
    for (const m of marks) {
      if (m.start < last) continue;
      if (m.start > last) frag.append(text.slice(last, m.start));
      frag.append(el("span", m.kind === "secret" ? "leak-hl" : "alias-hl", text.slice(m.start, m.end)));
      last = m.end;
    }
    frag.append(text.slice(last));
    ui.backdrop.replaceChildren(frag);
    ui.legend.hidden = false;
    moveBackdrop();
  }

  // Redactions become black bars, renamed identities become marker highlights.
  // Built with text nodes and textContent only, so the code is never parsed as HTML.
  function paint(text, tokens) {
    const parts = ["(\\[REDACTED_[A-Z0-9_]+_\\d{2,}\\])"];
    if (tokens.length) parts.push(`(${tokens.map(escapeRe).join("|")})`);
    const re = new RegExp(parts.join("|"), "gi");
    const frag = document.createDocumentFragment();
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) frag.append(text.slice(last, m.index));
      frag.append(el("mark", m[1] ? "redact" : "swapped", m[0]));
      last = m.index + m[0].length;
    }
    if (last < text.length) frag.append(text.slice(last));
    return frag;
  }

  function renderOutput() {
    const res = state.result;
    const text = !res ? "" : state.tab === "code" ? res.code : res.prompt;

    if (!text) ui.output.replaceChildren();
    else if (state.tab === "code" && text.length <= HIGHLIGHT_MAX) {
      const tokens = [...new Set(res.identities.map((i) => i.token))].sort((a, b) => b.length - a.length);
      ui.output.replaceChildren(paint(text, tokens));
    } else ui.output.replaceChildren(document.createTextNode(text));

    ui.output.scrollTop = ui.output.scrollLeft = 0;
    gutters.get(ui.output).setLines(countLines(text));
    gutters.get(ui.output).scrollTo(0);

    if (!res) ui.outMeta.textContent = "Waiting for something to scan";
    else if (state.tab === "prompt") ui.outMeta.textContent = `${text.length.toLocaleString()} characters`;
    else ui.outMeta.textContent = `${countLines(text).toLocaleString()} lines, ${res.findings.length} redacted`;
  }

  function renderLedger(findings) {
    ui.ledgerCount.textContent = findings.length;
    ui.ledger.replaceChildren();
    if (!findings.length) {
      ui.ledger.append(el("li", "nothing", state.result ? "Clean. No secrets found." : "Nothing flagged yet."));
      return;
    }
    const rows = findings.slice(0, LIMITS.ledgerRows).map((f) => {
      const body = el("div", "hit-body");
      body.append(el("b", "", f.label), el("small", "", `line ${f.line}, ${f.size} chars, entropy ${f.entropy.toFixed(2)}`));
      const li = el("li");
      li.append(el("span", `dot ${f.severity}`), body);
      li.title = f.mask;
      return li;
    });
    if (findings.length > LIMITS.ledgerRows) rows.push(el("li", "nothing", `+ ${findings.length - LIMITS.ledgerRows} more in the sanitized output`));
    ui.ledger.append(...rows);
  }

  function renderIdentities(list) {
    ui.idCount.textContent = list.length;
    ui.idList.replaceChildren();
    if (!list.length) {
      ui.idList.append(el("li", "nothing", "Anything in the list below gets swapped for a neutral token."));
      return;
    }
    ui.idList.append(...list.map((i) => {
      const li = el("li");
      const term = el("span", "term", i.term);
      term.title = i.term;
      li.append(term, el("span", "", "→"), el("code", "", i.token), el("span", "n", `×${i.count}`));
      return li;
    }));
  }

  function apply(res) {
    state.result = res;
    renderOutput();
    renderLedger(res.findings);
    renderIdentities(res.identities);
    paintSource(ui.source.value, res.marks);
    status(`${res.findings.length} secrets redacted, ${res.identities.length} names swapped`, res.stats.ms);
  }

  function reset() {
    state.result = null;
    renderOutput();
    renderLedger([]);
    renderIdentities([]);
    paintSource("", null);
    status("Ready");
  }

  const readOptions = () => ({
    threshold: parseFloat(ui.threshold.value),
    minLen: parseInt(ui.minLen.value, 10),
    watchlist: ui.watchlist.value,
    marks: ui.source.value.length <= HIGHLIGHT_MAX
  });

  // `commit` is the explicit Sanitize: only that run keeps new identity tokens.
  // Live runs use a fork. The ticket drops results that went stale while we
  // yielded to paint.
  async function run({ commit }) {
    const text = ui.source.value;
    if (!text.trim()) { reset(); return; }
    if (text.length > LIMITS.maxInput) { toast("Over 12 MB, that is too much for one go. Split it up and scan in chunks."); return; }

    const ticket = ++state.ticket;
    if (text.length > LIMITS.bigScan || commit) { setSeal("working"); status("Scanning…"); await nextFrame(); }
    if (ticket !== state.ticket) return;

    const res = scan(text, readOptions(), commit ? state.registry : state.registry.fork());
    apply(res);
    setSeal();
    if (commit) toast(`Done: ${res.findings.length} secrets redacted, ${res.identities.length} names swapped.`);
  }

  let liveTimer = 0;
  function scheduleLive() {
    clearTimeout(liveTimer);
    ++state.ticket;
    renderSourceMeta();
    paintSource("", null);
    const text = ui.source.value;
    if (!text.trim()) { reset(); return; }
    if (text.length > LIMITS.liveInput) { status("Big paste. Hit Sanitize when you want it scanned."); return; }
    liveTimer = setTimeout(() => run({ commit: false }), text.length > LIMITS.bigScan ? 900 : 280);
  }

  function clearAll() {
    clearTimeout(liveTimer);
    ++state.ticket;
    state.registry = new IdentityRegistry();
    ui.source.value = "";
    renderSourceMeta();
    reset();
    ui.source.focus();
  }

  function resetMap() {
    state.registry = new IdentityRegistry();
    toast("Name tokens wiped.");
    if (ui.source.value.trim()) run({ commit: true }); else renderIdentities([]);
  }

  async function copyActive() {
    if (!state.result) { toast("Run a sanitize first, there is nothing to use yet."); return; }
    const text = state.tab === "code" ? state.result.code : state.result.prompt;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Some browsers refuse the async clipboard on file:// pages.
      const range = document.createRange();
      range.selectNodeContents(ui.output);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      if (!document.execCommand("copy")) { toast("Browser said no to copying. Select the output and copy it yourself."); return; }
    }
    toast(state.tab === "code" ? "Cleaned code copied." : "Prompt copied.");
  }

  function exportBundle() {
    const res = state.result;
    if (!res) { toast("Run a sanitize first, there is nothing to use yet."); return; }
    const ledger = res.findings.length
      ? res.findings.map((f) => `${String(f.line).padStart(5)}  ${f.severity.padEnd(8)} ${f.label} -> ${f.mask}`).join("\n")
      : "(none)";
    const body = [
      "ZeroLeak export", `Generated: ${new Date().toISOString()}`,
      "The identity map is not included in this file.", "",
      "=== SANITIZED CODE ===", res.code, "",
      "=== AI PROMPT ===", res.prompt, "",
      "=== FINDINGS ===", ledger
    ].join("\n");

    const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
    const link = Object.assign(document.createElement("a"), { href: url, download: `zeroleak-${new Date().toISOString().replace(/[:.]/g, "-")}.txt` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Saved to your device. Nothing got uploaded.");
  }

  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll(".out-tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === tab)));
    renderOutput();
  }

  // all fake creds, none of these are real. don't paste real ones here either
  const SAMPLE = `// nightingale/services/billing-orchestrator.ts
// Owner: Core Platform @ Vantage Systems Inc
// Confidential: Project Nightingale settlement mesh

import { createPool } from "./db";

export const AWS_ACCESS_KEY_ID = "AKIA4Q7ZR2XK9WPLMN3T";
export const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
export const STRIPE_SECRET_KEY: string = "sk_live_51Nx8QpLk2AbCdEfGhIjKlMnOpQrStUvWxYz0123";
export const SESSION_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuaWdodGluZ2FsZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const NIGHTINGALE_GATEWAY = "https://api.vantage-systems.internal/settle";
const CACHE_SIGNING_TOKEN = "Zk9xQ2pW7mL4nR8tY6vB3sD1fG5hJ0kA";
const DATABASE_URL = "postgres://admin:S3cr3tP%40ssw0rd@db.internal:5432/nightingale_prod";
const config = { "password": "hunter2-prod-2024", region: "us-east-1" };
const EDGE_PRIVATE_KEY = \`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7bq9Zk4mQ2pW7mL4nR8tY6vB3sD1fG5hJ0kAZk9xQ2pW7mL4
nR8tY6vB3sD1fG5hJ0kAZk9xQ2pW7mL4nR8tY6vB3sD1fG5hJ0kAZk9xQ2pW7mL4
-----END RSA PRIVATE KEY-----\`;

// Project Nightingale settlement orchestrator.
export class NightingaleSettlementEngine {
  constructor() {
    this.pool = createPool(DATABASE_URL);
    this.gateway = NIGHTINGALE_GATEWAY;
    this.key = EDGE_PRIVATE_KEY;
  }

  async settle(invoice, attempt = 0) {
    const res = await fetch(this.gateway + "/v1/settle", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + SESSION_JWT,
        "X-Signing-Key": CACHE_SIGNING_TOKEN,
        "X-Org": "Vantage Systems Inc"
      },
      body: JSON.stringify(invoice)
    });
    if (res.status === 429 && attempt < 3) {
      await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
      return this.settle(invoice, attempt + 1);
    }
    return res.json();
  }
}
`;

  function init() {
    const isApple = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
    document.querySelectorAll(".cmd-key").forEach((k) => { k.textContent = isApple ? "⌘" : "Ctrl"; });

    $("demo-btn").addEventListener("click", () => {
      ui.source.value = SAMPLE;
      ui.source.scrollTop = 0;
      renderSourceMeta();
      run({ commit: true });
    });
    $("scrub-btn").addEventListener("click", () => run({ commit: true }));
    $("copy-btn").addEventListener("click", copyActive);
    $("save-btn").addEventListener("click", exportBundle);
    $("wipe-btn").addEventListener("click", clearAll);
    $("reset-names-btn").addEventListener("click", resetMap);
    document.querySelectorAll(".out-tab").forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));

    ui.source.addEventListener("input", scheduleLive);
    ui.watchlist.addEventListener("input", scheduleLive);
    ui.threshold.addEventListener("input", () => { ui.thresholdOut.textContent = parseFloat(ui.threshold.value).toFixed(2); scheduleLive(); });
    ui.minLen.addEventListener("input", () => { ui.minLenOut.textContent = ui.minLen.value; scheduleLive(); });

    document.addEventListener("keydown", (e) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key === "Enter") { e.preventDefault(); run({ commit: true }); }
      // Ctrl+Shift+C is taken by DevTools in Chrome, hence K.
      else if (mod && e.shiftKey && e.key.toLowerCase() === "k") { e.preventDefault(); copyActive(); }
    });

    renderSourceMeta();
    reset();
    setSeal();
  }

  init();
})();
