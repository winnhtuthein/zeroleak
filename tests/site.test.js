/*
 * ZeroLeak. Copyright (C) 2026 Winn Htut Hein.
 * SPDX-License-Identifier: AGPL-3.0-or-later. See LICENSE and NOTICE.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { check } = require("../scripts/check-site.js");

const ROOT = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");

test("site check: links, anchors, versions and legal pages are consistent", (t) => {
  const { errors, warnings } = check();
  warnings.forEach((w) => t.diagnostic(w));
  assert.deepEqual(errors, []);
});

test("scanner code makes no network calls", () => {
  // The sample text shown by "Try a sample" contains a fake fetch(); it is a string, not code.
  const strip = (s) => s.replace(/const SAMPLE = `(?:\\.|[^`\\])*`;/, "");
  const banned = /\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|localStorage|sessionStorage|indexedDB)\b|\bimport\s*\(|\.src\s*=|new\s+Image\b/;
  for (const f of ["engine.js", "app.js"]) {
    const src = strip(read(f));
    assert.ok(!/const SAMPLE/.test(src), "sample string should have been stripped from " + f);
    const hit = src.match(banned);
    assert.equal(hit, null, `${f} uses ${hit && hit[0]}`);
  }
});

test("index.html: CSP allows only same-origin scripts and requests, and loads only local files", () => {
  const html = read("index.html");
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /connect-src 'self'/);
  assert.match(csp, /form-action 'none'/);
  assert.ok(!/unsafe-inline|unsafe-eval|\*|https?:/.test(csp), "CSP must stay strict: " + csp);
  for (const m of html.matchAll(/<(?:script|link|img|iframe)\b[^>]*?\s(?:src|href)="([^"]+)"/g)) {
    assert.ok(!/^(https?:)?\/\//.test(m[1]), "remote resource: " + m[1]);
  }
  assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>/.test(html), "no inline scripts");
  assert.ok(html.includes('src="analytics.js"'));
});

test("document pages use a strict CSP and no inline scripts", () => {
  for (const f of ["privacy.html", "terms.html", "disclaimer.html", "licenses.html", "changelog.html"]) {
    const html = read(f);
    assert.match(html, /default-src 'none'/, f);
    assert.ok(!/unsafe-inline|unsafe-eval/.test(html), f);
    assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>/.test(html), f + " has inline script");
    assert.ok(html.includes('src="analytics.js"'), f + " should load analytics.js");
  }
});

test("privacy policy states the facts the code relies on", () => {
  const html = read("privacy.html");
  for (const phrase of ["Do Not Track", "Global Privacy Control", "no cookies", "Vercel"]) {
    assert.ok(html.includes(phrase), "privacy.html should mention " + phrase);
  }
});

// --- analytics.js gating ---
function runAnalytics({ protocol = "https:", hostname = "zeroleak.example", nav = {}, win = {} } = {}) {
  const appended = [];
  const document = {
    head: { appendChild: (el) => appended.push(el) },
    createElement: () => ({}),
  };
  const window = { navigator: nav, location: { protocol, hostname }, document, ...win };
  vm.runInNewContext(read("analytics.js"), { window, document, navigator: nav });
  return { appended, window };
}

test("analytics loads the Vercel script on a real https site", () => {
  const { appended, window } = runAnalytics();
  assert.equal(appended.length, 1);
  assert.equal(appended[0].src, "/_vercel/insights/script.js");
  assert.equal(typeof window.va, "function");
});

test("analytics stays off for opt-out signals and non-production hosts", () => {
  const cases = {
    "Do Not Track": { nav: { doNotTrack: "1" } },
    "Global Privacy Control": { nav: { globalPrivacyControl: true } },
    "file:": { protocol: "file:", hostname: "" },
    "http:": { protocol: "http:" },
    localhost: { hostname: "localhost" },
    "127.0.0.1": { hostname: "127.0.0.1" },
    "LAN name": { hostname: "mypc.local" },
  };
  for (const [name, opts] of Object.entries(cases)) {
    assert.equal(runAnalytics(opts).appended.length, 0, name + " should not load analytics");
  }
});

test("analytics.js never reads page content", () => {
  const src = read("analytics.js").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.ok(!/getElementById|querySelector|textarea|clipboard|\.value\b|innerText|textContent/.test(src));
});
