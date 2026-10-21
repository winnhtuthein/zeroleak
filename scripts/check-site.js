/*
 * ZeroLeak. Copyright (C) 2026 Winn Htut Hein.
 * SPDX-License-Identifier: AGPL-3.0-or-later. See LICENSE and NOTICE.
 */

// Site hygiene check. Run: npm run check   (add --strict to fail on unfilled placeholders)
// Verifies internal links and #anchors, version consistency, legal-page structure and CSP presence.
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const LEGAL = ["privacy.html", "terms.html", "disclaimer.html", "licenses.html"];

function check() {
  const errors = [];
  const warnings = [];
  const read = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
  const pages = fs.readdirSync(ROOT).filter((f) => f.endsWith(".html"));
  const ids = {};
  for (const p of pages) ids[p] = new Set([...read(p).matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));

  for (const p of pages) {
    const html = read(p);
    if (!/<meta http-equiv="Content-Security-Policy"/.test(html)) errors.push(`${p}: missing CSP meta tag`);
    for (const m of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
      const url = m[1];
      if (/^(https?:|mailto:|data:)/.test(url) || url.includes("{{")) continue;
      const [file, hash] = url.split("#");
      const target = file === "" ? p : file.split("?")[0];
      if (!fs.existsSync(path.join(ROOT, target))) { errors.push(`${p}: broken link ${url}`); continue; }
      if (hash && target.endsWith(".html") && !ids[target]?.has(hash)) errors.push(`${p}: missing anchor #${hash} in ${target}`);
    }
  }

  const version = JSON.parse(read("package.json")).version;
  const clHtml = read("changelog.html");
  if (!clHtml.includes(`Current version ${version}`)) errors.push(`changelog.html: current version is not ${version}`);
  if (!new RegExp(`^## \\[${version.replace(/\./g, "\\.")}\\] - \\d{4}-\\d{2}-\\d{2}`, "m").test(read("CHANGELOG.md"))) errors.push(`CHANGELOG.md: no entry for ${version}`);
  if (!read("index.html").includes(`>v${version}</a>`)) errors.push(`index.html: footer version is not v${version}`);
  for (const p of pages.filter((f) => f !== "index.html")) {
    if (!read(p).includes(`ZeroLeak v${version}`)) errors.push(`${p}: footer version is not v${version}`);
  }

  for (const p of LEGAL) {
    const html = read(p);
    if (!/<p class="meta"><span>Version \d+\.\d+<\/span>/.test(html)) errors.push(`${p}: missing version/effective-date line`);
    if (!/id="history"/.test(html)) errors.push(`${p}: missing version history`);
    const rows = [...html.matchAll(/<tr><td>(\d+\.\d+)<\/td>/g)].map((m) => m[1]);
    const meta = html.match(/<span>Version (\d+\.\d+)<\/span>/)?.[1];
    if (rows.length === 0 || rows[0] !== meta) errors.push(`${p}: top history row (${rows[0]}) does not match stated version (${meta})`);
  }

  for (const f of [...pages, ".well-known/security.txt"]) {
    const found = [...new Set(read(f).match(/\{\{[A-Z_]+\}\}/g) || [])];
    if (found.length) warnings.push(`${f}: unfilled placeholder ${found.join(", ")}`);
  }
  return { errors, warnings };
}

module.exports = { check };

if (require.main === module) {
  const { errors, warnings } = check();
  const strict = process.argv.includes("--strict");
  warnings.forEach((w) => console.log(`${strict ? "ERROR" : "warn "} ${w}`));
  errors.forEach((e) => console.log(`ERROR ${e}`));
  if (errors.length || (strict && warnings.length)) process.exit(1);
  console.log(errors.length ? "" : `ok (${warnings.length} placeholder warning${warnings.length === 1 ? "" : "s"})`);
}
