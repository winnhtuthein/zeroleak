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

// Run with: node --test
const test = require("node:test");
const assert = require("node:assert/strict");
const { scan, IdentityRegistry } = require("../engine.js");

const opts = (extra = {}) => ({ threshold: 4.2, minLen: 16, watchlist: "", ...extra });
const run = (text, extra) => scan(text, opts(extra), new IdentityRegistry());

test("redacts well-known credential formats", () => {
  const src = [
    'const a = "AKIA4Q7ZR2XK9WPLMN3T";',
    'const s = "sk_live_51Nx8QpLk2AbCdEfGhIjKlMnOpQrStUvWxYz0123";',
    'const d = "postgres://admin:pw@db.internal:5432/app";'
  ].join("\n");
  const { code, findings } = run(src);
  assert.equal(findings.length, 3);
  assert.doesNotMatch(code, /AKIA4Q7|sk_live|admin:pw/);
});

test("catches JSON and TypeScript style assignments", () => {
  const { code } = run('{ "password": "hunter2-prod-2024" }\nconst API_KEY: string = "abcd1234efgh5678";');
  assert.doesNotMatch(code, /hunter2|abcd1234/);
});

test("same secret reuses one placeholder, different secrets never collide", () => {
  const src = 'a = "AKIA4Q7ZR2XK9WPLMN3T"\nb = "AKIA4Q7ZR2XK9WPLMN3T"\nc = "AKIA9ZZZZZZZZZZZZZZZ"';
  const { findings } = run(src);
  assert.equal(findings[0].mask, findings[1].mask);
  assert.notEqual(findings[0].mask, findings[2].mask);
});

test("multi-line private keys are redacted as one block", () => {
  const body = "MIIEowIBAAKCAQEA7bq9Zk4mQ2pW7mL4nR8tY6vB3sD1fG5hJ0kAZk9xQ2pW7mL4";
  const key = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n${body}\n-----END RSA PRIVATE KEY-----`;
  const { code, findings } = run(`const k = \`${key}\`;`);
  assert.equal(findings.length, 1);
  assert.doesNotMatch(code, /MIIEow/);
});

test("ordinary strings, URLs and paths are left alone", () => {
  const src = 'const a = "hello world, this is just text";\nconst u = "https://example.com/a/b/c?x=1";\nconst p = "./src/components/Button.tsx";';
  assert.equal(run(src).findings.length, 0);
});

test("placeholders like changeme are not flagged", () => {
  assert.equal(run('password = "changeme"').findings.length, 0);
});

test("identity matching handles case, camelCase and snake_case, keeps casing", () => {
  const src = "nightingale/x\nNIGHTINGALE_GATEWAY\nNightingaleEngine\nNightingales";
  const { code } = run(src, { watchlist: "Nightingale" });
  assert.match(code, /^systemalpha\/x/);
  assert.match(code, /SYSTEMALPHA_GATEWAY/);
  assert.match(code, /SystemAlphaEngine/);
  assert.match(code, /Nightingales$/); // inside a longer word: untouched
});

test("watchlist supports forced tokens", () => {
  const { code } = run("Acme Corp ships it", { watchlist: "Acme Corp => Vendor" });
  assert.equal(code, "Vendor ships it");
});

test("live scans on a fork do not pollute the committed registry", () => {
  const committed = new IdentityRegistry();
  scan("Project Nig", opts(), committed.fork());
  scan("Project Nightingale", opts(), committed.fork());
  const final = scan("Project Nightingale", opts(), committed);
  assert.equal(final.identities[0].token, "ProjectAlpha");
});

test("an unterminated-quote file of ~4 MB scans in well under 3 seconds", () => {
  let big = "";
  for (let i = 0; i < 60000; i++) big += `// don't do this, it's x = 'a' ${i}\n`;
  const t = performance.now();
  run(big);
  assert.ok(performance.now() - t < 3000);
});

test("empty and whitespace input do not throw", () => {
  assert.equal(run("").findings.length, 0);
  assert.equal(run("   \n\n").findings.length, 0);
});

// Fake credentials in each vendor's documented shape, from a seeded generator so they are random-looking but never real.
function fake(chars, n, seed) {
  let x = seed * 2654435761 >>> 0, out = "";
  for (let i = 0; i < n; i++) { x = (x * 1664525 + 1013904223) >>> 0; out += chars[(x >>> 8) % chars.length]; }
  return out;
}
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef", B64URL = ALNUM + "-_", LETTERS = ALNUM.slice(0, 52);

const VENDORS = [
  ["Anthropic API key", `sk-ant-api03-${fake(B64URL, 60, 1)}`],
  ["GitLab token", `glpat-${fake(B64URL, 20, 2)}`],
  ["npm token", `npm_${fake(ALNUM, 36, 3)}`],
  ["PyPI token", `pypi-AgEIcHlwaS5vcmc${fake(B64URL, 70, 4)}`],
  ["Hugging Face token", `hf_${fake(LETTERS, 34, 5)}`],
  ["SendGrid key", `SG.${fake(B64URL, 22, 6)}.${fake(B64URL, 43, 7)}`],
  ["Stripe webhook secret", `whsec_${fake(ALNUM, 32, 8)}`],
  ["Shopify token", `shpat_${fake(HEX, 32, 9)}`],
  ["DigitalOcean token", `dop_v1_${fake(HEX, 64, 10)}`],
  ["Databricks token", `dapi${fake(HEX, 32, 11)}`],
  ["Google OAuth client secret", `GOCSPX-${fake(B64URL, 28, 12)}`],
  ["Twilio key", `SK${fake(HEX, 32, 13)}`],
  ["Slack webhook", `https://hooks.slack.com/services/T00000000/B00000000/${fake(ALNUM, 24, 14)}`],
  ["Discord webhook", `https://discord.com/api/webhooks/123456789012345678/${fake(B64URL, 68, 15)}`],
  ["Telegram bot token", `123456789:AA${fake(B64URL, 33, 16)}`],
  ["Azure storage key", `DefaultEndpointsProtocol=https;AccountName=x;AccountKey=${fake(ALNUM, 86, 17)}==;EndpointSuffix=core.windows.net`, fake(ALNUM, 86, 17)],
  ["Password in URL", "https://deploy:Tr0ub4dor-9x@git.example.com/repo.git", "Tr0ub4dor-9x"],
  ["Basic auth header", "Authorization: Basic dXNlcjpzdXBlcnNlY3JldHBhc3M=", "dXNlcjpzdXBlcnNlY3JldHBhc3M"]
];

for (const [label, secret, leak = secret] of VENDORS) {
  test(`detects ${label}`, () => {
    const { findings, code } = run(`const x = "${secret}";`);
    assert.ok(findings.some((f) => f.label === label), `${label} not found in: ${secret}`);
    assert.ok(!code.includes(leak), `${label} leaked into the output`);
  });
}

test("things that look like secrets but are not stay untouched", () => {
  const benign = [
    'const k = "sha512-fNAjWnA/nZ2jz31kxR/AqRaUT8ewHBw/WuBIosK0moMy1C9e5ValbDfFdIxJzVOabc==";',
    'id = "AKIAIOSFODNN7EXAMPLE"',
    'cls = "sk-toggleable__label-arrow"',
    'url = "postgres:///db_name"',
    '// Basic configuration steps for the server',
    'const msg = { password: "Please enter your password" };',
    'const t = { type: "password", token: "bearerTokenAuthenticationPolicy" };',
    'const e = { code: "auth/invalid-api-key", MAX_TOKENS: "MAX_TOKENS" };',
    'const n = "model.layers.0.self_attn.q_proj.weight_scale_inv";',
    'const a = "arn:aws:iam::123456789012:role/AWSExampleRole01";',
    'const r = "].number,utf8_validation=_FEATURESET.values_by_name[";',
    'const v = { token: "^3.0.0 || ^4.0.0" };'
  ];
  for (const line of benign) assert.equal(run(line).findings.length, 0, `false positive: ${line}`);
});

test("a long run of random-looking base64 data is not treated as a token", () => {
  assert.equal(run(`const img = "${fake(ALNUM, 400, 99)}";`).findings.length, 0);
});

test("findings carry offsets into the original text", () => {
  const src = 'a\nconst k = "AKIA4Q7ZR2XK9WPLMN3T";';
  const { findings } = run(src);
  assert.equal(src.slice(findings[0].start, findings[0].end), "AKIA4Q7ZR2XK9WPLMN3T");
});

test("marks cover secrets and names in the original text, and skip names inside secrets", () => {
  const src = 'org = "Acme Corp"\nurl = "postgres://u:p4ss@acme-corp.internal/db"';
  const { marks } = run(src, { watchlist: "Acme Corp", marks: true });
  const hit = (k) => marks.filter((m) => m.kind === k).map((m) => src.slice(m.start, m.end));
  assert.deepEqual(hit("name"), ["Acme Corp"]);
  assert.ok(hit("secret").some((s) => s.startsWith("postgres://")));
});
