// ZeroLeak. Copyright (C) 2026 Winn Htut Hein. SPDX-License-Identifier: AGPL-3.0-or-later.
// Runs the scanner over a folder of real code and prints what it flags.
// Public code has almost no live secrets, so most hits are false positives:
// use it to tune detectors. Usage: node scripts/corpus-scan.js <folder> [show]
const fs = require("fs");
const path = require("path");
const { scan, IdentityRegistry } = require("../engine.js");

const [root, show = "0"] = process.argv.slice(2);
if (!root) { console.error("usage: node scripts/corpus-scan.js <folder> [samples-per-class]"); process.exit(1); }

const EXT = new Set([".js", ".ts", ".py", ".json", ".yml", ".yaml", ".env", ".toml", ".cfg", ".ini", ".md", ".sh", ".mjs", ".cjs", ".java", ".go", ".rb"]);
const files = [];
(function walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p); else if (EXT.has(path.extname(e.name))) files.push(p);
  }
})(root);

const counts = {}, samples = {};
let bytes = 0, scanned = 0, slowest = 0;
for (const file of files) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { continue; }
  if (text.length > 3e6) continue;
  bytes += text.length; scanned++;
  const res = scan(text, { threshold: 4.2, minLen: 16, watchlist: "" }, new IdentityRegistry());
  slowest = Math.max(slowest, res.stats.ms);
  for (const f of res.findings) {
    counts[f.label] = (counts[f.label] || 0) + 1;
    const list = (samples[f.label] ||= []);
    if (list.length < Number(show)) list.push(`${path.relative(root, file)}:${f.line}  ${text.slice(f.start, f.end).slice(0, 80)}`);
  }
}
console.log(`${scanned} files, ${(bytes / 1e6).toFixed(1)} MB, slowest file ${slowest.toFixed(0)} ms`);
console.table(counts);
for (const [label, list] of Object.entries(samples)) { console.log(`\n${label}`); list.forEach((l) => console.log("  " + l)); }
