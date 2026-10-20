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

// Scanner only. No DOM, no network.
// Loaded as a plain script here, and with require() in the tests.
(function (root) {
  "use strict";

  const LIMITS = {
    maxInput: 12_000_000,   // the textarea chokes before the scanner does
    liveInput: 1_500_000,   // bigger than this only scans on Sanitize
    bigScan: 200_000,
    maxToken: 160,    // longer quoted blobs are data, not tokens; real long keys have their own pattern
    ledgerRows: 100
  };

  const GREEK = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu",
    "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega"];
  const TOKEN_PREFIX = { project: "Project", org: "Org", system: "System" };
  const ORG_SUFFIX = "Inc|LLC|Corp|Corporation|Labs|Technologies|Systems|Dynamics|Group";

  const encoder = new TextEncoder();
  const byteLength = (s) => encoder.encode(s).length;
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const countLines = (s) => {
    if (!s) return 0;
    let n = 1, i = -1;
    while ((i = s.indexOf("\n", i + 1)) !== -1) n++;
    return n;
  };

  const formatBytes = (n) =>
    n < 1024 ? `${n} B` : n < 1_048_576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1_048_576).toFixed(2)} MB`;

  // Shannon entropy in bits/char plus which character classes appear.
  // Latin-1 counts go in a typed array; anything wider falls back to a Map.
  function analyze(str) {
    const table = new Uint32Array(256);
    const wide = new Map();
    let lower = 0, upper = 0, digit = 0, other = 0;

    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      if (c < 256) table[c]++; else wide.set(c, (wide.get(c) || 0) + 1);
      if (c >= 97 && c <= 122) lower = 1;
      else if (c >= 65 && c <= 90) upper = 1;
      else if (c >= 48 && c <= 57) digit = 1;
      else other = 1;
    }

    let entropy = 0;
    const add = (count) => {
      if (!count) return;
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    };
    for (let i = 0; i < 256; i++) add(table[i]);
    wide.forEach(add);

    return { entropy, classes: lower + upper + digit + other, hasDigit: digit === 1 };
  }

  // "changeme", "${TOKEN}", "<your key>" and friends

  const PLACEHOLDER = /^(?:[x*.#-]+|your[\w-]*|<.*>|\$\{.*\}|\{\{.*\}\}|change[-_]?me|placeholder|(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|credential)s?|example.*|process\.env.*)$/i;
  const notPlaceholder = (value) => !PLACEHOLDER.test(value);

  // Values a human wrote as a label or enum, not as a secret: camelCase,
  // SCREAMING_SNAKE, kebab-case, version ranges, or a sentence ("Enter your password").
  const IDENTIFIER_LIKE = /^(?:[a-z]+(?:[A-Z][a-z0-9]*)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z][a-z]+(?:[A-Z][a-z]+)*|[A-Z]{3,}|[a-z]+(?:[-_][a-z]+)+|[a-z]+\/[a-z]+(?:-[a-z]+)*|[a-z]+#[A-Za-z]+|[A-Z]+(?:[-_][A-Z]+)+|[A-Za-z]+(?:\.[A-Za-z]+)+|%\(\w+\)s|[\^~<>=v\d.x*\s|-]+)$/;
  const SENTENCE = /^[A-Za-z][A-Za-z'",.!?:()-]*(?: [A-Za-z'",.!?:()-]+){2,}$/;
  const plausibleSecret = (value) => notPlaceholder(value) && !IDENTIFIER_LIKE.test(value) && !SENTENCE.test(value);

  // AWS's documentation keys end in EXAMPLE; a private-key "block" with no long
  // base64 run is a placeholder like <a very long private key string>.
  const notDocsExample = (value) => !/EXAMPLE$/.test(value);
  const hasKeyBody = (value) => /[A-Za-z0-9+/=]{40,}/.test(value.replace(/\s+/g, ""));

  // The `d` flag gives exact capture offsets. `group` is the capture that holds
  // the secret; without it the whole match is redacted. Quantifiers are bounded
  // on purpose so a hostile file can't make a pattern run away.
  const DETECTORS = [
    { label: "Private key", severity: "critical", prefix: "REDACTED_PRIVATE_KEY", accept: hasKeyBody,
      re: /-----BEGIN ((?:[A-Z]+ )*)PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,8000}?-----END \1PRIVATE KEY(?: BLOCK)?-----/dg },
    { label: "AWS access key ID", severity: "critical", prefix: "REDACTED_AWS_ACCESS_KEY", accept: notDocsExample,
      re: /\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/dg },
    { label: "AWS secret key", severity: "critical", prefix: "REDACTED_AWS_SECRET_KEY", group: 2,
      re: /\b(?:aws_)?secret_access_key["']?\s*[:=]\s*(["'])([A-Za-z0-9/+=]{40})\1/dgi },
    { label: "Stripe secret key", severity: "critical", prefix: "REDACTED_STRIPE_SECRET",
      re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/dg },
    { label: "JSON Web Token", severity: "high", prefix: "REDACTED_JWT",
      re: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/dg },
    { label: "GitHub token", severity: "critical", prefix: "REDACTED_GITHUB_TOKEN",
      re: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_\w{40,})\b/dg },
    { label: "Google API key", severity: "high", prefix: "REDACTED_GOOGLE_API_KEY",
      re: /\bAIza[\w-]{35}\b/dg },
    { label: "Slack token", severity: "high", prefix: "REDACTED_SLACK_TOKEN",
      re: /\bxox[abprs]-[0-9A-Za-z-]{10,}/dg },
    { label: "Anthropic API key", severity: "critical", prefix: "REDACTED_ANTHROPIC_KEY",
      re: /\bsk-ant-[a-z0-9]{2,6}-[\w-]{30,}/dgi },
    { label: "OpenAI-style key", severity: "critical", prefix: "REDACTED_OPENAI_KEY", accept: (v) => /\d/.test(v) && !wordy(v),
      re: /\bsk-(?:proj-)?[\w-]{20,}/dg },
    { label: "GitLab token", severity: "critical", prefix: "REDACTED_GITLAB_TOKEN",
      re: /\bglpat-[\w-]{20}\b/dg },
    { label: "npm token", severity: "critical", prefix: "REDACTED_NPM_TOKEN",
      re: /\bnpm_[A-Za-z0-9]{36}\b/dg },
    { label: "PyPI token", severity: "critical", prefix: "REDACTED_PYPI_TOKEN",
      re: /\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}/dg },
    { label: "Hugging Face token", severity: "high", prefix: "REDACTED_HF_TOKEN",
      re: /\bhf_[A-Za-z]{34}\b/dg },
    { label: "SendGrid key", severity: "critical", prefix: "REDACTED_SENDGRID_KEY",
      re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/dg },
    { label: "Stripe webhook secret", severity: "high", prefix: "REDACTED_STRIPE_WEBHOOK",
      re: /\bwhsec_[A-Za-z0-9]{24,}\b/dg },
    { label: "Shopify token", severity: "critical", prefix: "REDACTED_SHOPIFY_TOKEN",
      re: /\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b/dg },
    { label: "DigitalOcean token", severity: "critical", prefix: "REDACTED_DO_TOKEN",
      re: /\bdo[opr]_v1_[a-f0-9]{64}\b/dg },
    { label: "Databricks token", severity: "high", prefix: "REDACTED_DATABRICKS_TOKEN",
      re: /\bdapi[a-f0-9]{32}\b/dg },
    { label: "Google OAuth client secret", severity: "high", prefix: "REDACTED_GOOGLE_OAUTH_SECRET",
      re: /\bGOCSPX-[\w-]{28}\b/dg },
    { label: "Twilio key", severity: "high", prefix: "REDACTED_TWILIO_KEY",
      re: /\bSK[0-9a-f]{32}\b/dg },
    { label: "Slack webhook", severity: "high", prefix: "REDACTED_SLACK_WEBHOOK",
      re: /\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[\w/-]{20,}/dg },
    { label: "Discord webhook", severity: "high", prefix: "REDACTED_DISCORD_WEBHOOK",
      re: /\bhttps:\/\/(?:discord(?:app)?\.com)\/api\/webhooks\/\d{17,20}\/[\w-]{60,}/dg },
    { label: "Telegram bot token", severity: "high", prefix: "REDACTED_TELEGRAM_TOKEN",
      re: /\b\d{8,10}:AA[\w-]{33}\b/dg },
    { label: "Azure storage key", severity: "critical", prefix: "REDACTED_AZURE_KEY", group: 1,
      re: /\b(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)/dg },
    { label: "Password in URL", severity: "critical", prefix: "REDACTED_URL_PASSWORD", group: 1, accept: notPlaceholder,
      re: /\bhttps?:\/\/[^\s:@/"'`<>]{1,64}:([^\s@/"'`<>]{3,64})@/dg },
    { label: "Basic auth header", severity: "high", prefix: "REDACTED_BASIC_AUTH", group: 1, accept: (v) => /[\d+/=]/.test(v),
      re: /\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})/dg },
    { label: "Bearer token", severity: "high", prefix: "REDACTED_BEARER_TOKEN", group: 1,
      re: /\bBearer\s+([\w\-.~+/]{20,}=*)/dg },
    { label: "Internal hostname", severity: "high", prefix: "REDACTED_INTERNAL_HOST", group: 1,
      re: /\bhttps?:\/\/([a-z0-9.-]+\.(?:internal|local|corp|lan|intranet))\b/dgi },
    { label: "Connection string", severity: "critical", prefix: "REDACTED_CONNECTION_STRING", accept: (v) => /^[a-z+]+:\/\/[^/\s]/i.test(v),
      re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s"'`<>]+/dgi },
    { label: "Secret in .env style line", severity: "high", prefix: "REDACTED_CREDENTIAL", group: 1, accept: notPlaceholder,
      re: /^[ \t]*(?:export[ \t]+)?[A-Z0-9_]{0,40}(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|DSN)[ \t]*=[ \t]*([^\s"'#]{12,})[ \t]*$/dgm },
    // password = "x", "apiKey": "x" (JSON), const TOKEN: string = "x" (TypeScript)
    { label: "Assigned credential", severity: "medium", prefix: "REDACTED_CREDENTIAL", group: 2, accept: plausibleSecret,
      re: /\b[\w-]{0,40}(?:api[_-]?key|secret|token|password|passwd|pwd|credential)[\w-]{0,40}["']?(?:\s*:\s*[A-Za-z_][\w.<>[\]|]{0,40})?\s*[:=]\s*(["'`])([^"'`\n]{8,200})\1/dgi }
  ];

  // Single-line and length-capped: a stray apostrophe in a comment then costs
  // a few hundred steps, not a rescan of the rest of the file.
  const buildStringRe = (minLen) =>
    new RegExp(`(["'\`])([^\\s"'\`\\\\]{${minLen},${LIMITS.maxToken}})\\1`, "dg");

  // Random-looking strings that are really something else. All of these showed
  // up as false positives when the scanner was run over real packages.
  const NOT_A_SECRET = /^(?:[a-z][\w+.-]*:\/\/|data:|\.{0,2}\/|~\/|[A-Za-z]:\\|(?:sha(?:1|256|384|512)|md5)-|(?:pkg|arn|urn):|(?:application|audio|image|text|video|font|model|multipart)\/[a-z])/i; // URLs, paths, npm/SRI hashes, package and resource ids
  const CODE_PUNCTUATION = /[()[\]{};,<>]/;     // the "string" is really code between two quotes
  const ALPHABET_RUN = /abcdefg|ABCDEFG|0123456|9876543/;  // base64 alphabet constants
  const dottedName = (s) => s.includes(".") && s.split(".").every((p) => /^[~@$]?[A-Za-z_]{2,}\d{0,2}$/.test(p));
  // Mostly dictionary-shaped chunks joined by separators (model.layers.0.weight,
  // runwayml/stable-diffusion-v1-5): an id or a path, not a random token.
  function wordy(s) {
    const parts = s.split(/[^A-Za-z0-9]+/).filter(Boolean);
    if (parts.length < 3) return false;
    const letters = parts.filter((p) => /^[A-Za-z]{2,}\d{0,2}$/.test(p)).reduce((n, p) => n + p.length, 0);
    return letters / s.length >= 0.5;
  }
  const NON_ASCII = /[^\x00-\x7f]/;
  const looksLikeCode = (s) => NON_ASCII.test(s) || wordy(s) || NOT_A_SECRET.test(s) || CODE_PUNCTUATION.test(s) || ALPHABET_RUN.test(s) || dottedName(s);

  // binary search, intervals are sorted and never overlap
  function intersects(sorted, start, end) {
    let lo = 0, hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (sorted[mid].end <= start) lo = mid + 1; else hi = mid;
    }
    return lo < sorted.length && sorted[lo].start < end;
  }

  // earlier position wins, then earlier detector, then longer match
  function resolveOverlaps(candidates) {
    candidates.sort((a, b) => a.start - b.start || a.rank - b.rank || b.end - a.end);
    const kept = [];
    let edge = 0;
    for (const c of candidates) {
      if (c.start >= edge) { kept.push(c); edge = c.end; }
    }
    return kept;
  }

  function collectPatternMatches(text) {
    const out = [];
    DETECTORS.forEach((det, rank) => {
      const re = new RegExp(det.re.source, det.re.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        const [start, end] = det.group ? m.indices[det.group] : m.indices[0];
        if (det.accept && !det.accept(text.slice(start, end))) continue;
        out.push({ start, end, rank, label: det.label, severity: det.severity, prefix: det.prefix });
      }
    });
    return out;
  }

  // random-looking quoted strings that no pattern already claimed
  function collectEntropyMatches(text, blocked, opts) {
    const re = buildStringRe(opts.minLen);
    const hits = [];
    let scanned = 0, m;
    while ((m = re.exec(text)) !== null) {
      scanned++;
      const [start, end] = m.indices[2];
      const body = m[2];
      if (looksLikeCode(body) || intersects(blocked, start, end)) continue;
      const stats = analyze(body);
      if (stats.entropy < opts.threshold) continue;
      // mixed classes only: digits plus letters, or all four
      if (!(stats.hasDigit ? stats.classes >= 3 : stats.classes === 4)) continue;
      hits.push({ start, end, rank: 99, label: "High-entropy string", severity: "high", prefix: "REDACTED_HIGH_ENTROPY_KEY" });
    }
    return { hits, scanned };
  }

  // offset -> 1-based line number
  function lineLocator(text) {
    const starts = [0];
    let i = -1;
    while ((i = text.indexOf("\n", i + 1)) !== -1) starts.push(i + 1);
    return (offset) => {
      let lo = 0, hi = starts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
      }
      return lo + 1;
    };
  }

  // Placeholders are numbered per class in order of appearance, so the same
  // secret always maps to the same one and nothing is derived from the secret.
  function scan(text, opts, registry) {
    const t0 = performance.now();

    const byPattern = resolveOverlaps(collectPatternMatches(text));
    const { hits, scanned } = collectEntropyMatches(text, byPattern, opts);
    const accepted = byPattern.concat(hits).sort((a, b) => a.start - b.start);

    const lineOf = lineLocator(text);
    const seen = new Map();
    const counters = {};
    const parts = [];
    let cursor = 0;

    const findings = accepted.map((f) => {
      const secret = text.slice(f.start, f.end);
      const key = `${f.prefix}\0${secret}`;
      if (!seen.has(key)) seen.set(key, (counters[f.prefix] = (counters[f.prefix] || 0) + 1));
      const mask = `[${f.prefix}_${String(seen.get(key)).padStart(2, "0")}]`;
      parts.push(text.slice(cursor, f.start), mask);
      cursor = f.end;
      return {
        label: f.label, severity: f.severity, prefix: f.prefix, mask,
        start: f.start, end: f.end,
        line: lineOf(f.start), size: secret.length, entropy: analyze(secret).entropy
      };
    });
    parts.push(text.slice(cursor));

    const mapped = tokenizeIdentities(parts.join(""), opts.watchlist, registry);

    // opt-in: spans of the original text for the editor overlay
    const marks = opts.marks
      ? accepted.map((f) => ({ start: f.start, end: f.end, kind: "secret" }))
          .concat(identitySpans(text, opts.watchlist, accepted)).sort((a, b) => a.start - b.start)
      : [];

    return {
      code: mapped.text,
      prompt: buildPrompt(mapped.text, mapped.identities, findings),
      findings,
      identities: mapped.identities,
      marks,
      registry,
      stats: {
        lines: countLines(text), bytes: byteLength(text), strings: scanned,
        spikes: hits.length, ms: performance.now() - t0
      }
    };
  }

  // term -> token, kept for the session so names stay stable between scans
  class IdentityRegistry {
    constructor(from) {
      this.tokens = new Map(from ? from.tokens : []);
      this.counters = { ...(from ? from.counters : { Project: 0, Org: 0, System: 0 }) };
    }
    // live scans use a fork so a half-typed name never gets a permanent token
    fork() { return new IdentityRegistry(this); }

    tokenFor(term, category, forced) {
      const key = term.toLowerCase();
      if (forced) { this.tokens.set(key, forced); return forced; }
      if (this.tokens.has(key)) return this.tokens.get(key);
      const prefix = TOKEN_PREFIX[category];
      const n = this.counters[prefix]++;
      const token = prefix + (GREEK[n] ?? `Node${String(n - GREEK.length + 1).padStart(2, "0")}`);
      this.tokens.set(key, token);
      return token;
    }
  }

  const categoryOf = (term) =>
    /^Project\s/.test(term) ? "project" : new RegExp(`\\b(?:${ORG_SUFFIX})\\.?$`).test(term) ? "org" : "system";

  // "Term" or "Term => Token" per line, # for comments
  function parseWatchlist(raw) {
    const entries = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const [term, token = ""] = trimmed.split("=>").map((s) => s.trim());
      if (term.length < 3) continue;
      let forced = token.replace(/[^A-Za-z0-9]/g, "");
      if (forced && !/^[A-Za-z]/.test(forced)) forced = `T${forced}`;
      entries.push({ term, category: categoryOf(term), forced: forced || null });
    }
    return entries;
  }

  // names the user didn't list but that give themselves away
  function discoverIdentities(text) {
    const found = [];
    const rules = [
      { re: /\bProject[ \t]+[A-Z][A-Za-z0-9]{2,}\b/g, category: "project", pick: 0 },
      { re: new RegExp(`\\b(?:[A-Z][\\w&.-]*[ \\t]+){1,3}(?:${ORG_SUFFIX})\\b`, "g"), category: "org", pick: 0 },
      { re: /\binternal[-_][A-Za-z0-9][\w-]{2,}\b/gi, category: "system", pick: 0 },
      { re: /\b(?:codename|project)[ \t]*[:=][ \t]*(["'])([A-Z][\w -]{2,})\1/gi, category: "project", pick: 2 }
    ];
    for (const { re, category, pick } of rules) {
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        found.push({ term: m[pick].trim(), category, forced: null });
      }
    }
    return found;
  }

  // camelCase and snake_case seams count as word edges, so "Nightingale" matches
  // inside NightingaleEngine and NIGHTINGALE_GATEWAY but not inside "Nightingales"
  function atWordEdge(text, start, end) {
    const before = text[start - 1], after = text[end], first = text[start], last = text[end - 1];
    const alnum = (c) => /[A-Za-z0-9]/.test(c);
    const leftOk = !before || !alnum(before) || (/[a-z]/.test(before) && /[A-Z]/.test(first));
    const rightOk = !after || !alnum(after) || (/[a-z]/.test(last) && /[A-Z]/.test(after));
    return leftOk && rightOk;
  }

  // nightingale -> systemalpha, NIGHTINGALE -> SYSTEMALPHA
  function matchCase(token, original) {
    if (original.length > 1 && original === original.toUpperCase() && /[A-Z]/.test(original)) return token.toUpperCase();
    if (original === original.toLowerCase()) return token.toLowerCase();
    return token;
  }

  // watchlist first so explicit tokens beat auto-detection
  function collectEntries(text, watchlistRaw) {
    const entries = new Map();
    const lower = text.toLowerCase();
    for (const e of [...parseWatchlist(watchlistRaw), ...discoverIdentities(text)]) {
      const key = e.term.toLowerCase();
      if (!entries.has(key) && lower.includes(key)) entries.set(key, e);
    }
    return entries;
  }

  // one longest-first regex: single pass, and tokens never get re-replaced
  const identityRegex = (entries) =>
    new RegExp([...entries.keys()].sort((a, b) => b.length - a.length).map(escapeRe).join("|"), "gi");

  // where names sit in the original text, skipping any that live inside a redacted secret
  function identitySpans(text, watchlistRaw, secrets) {
    const entries = collectEntries(text, watchlistRaw);
    if (!entries.size) return [];
    const re = identityRegex(entries), spans = [];
    let m;
    while ((m = re.exec(text)) !== null) {
      const start = m.index, end = start + m[0].length;
      if (atWordEdge(text, start, end) && !intersects(secrets, start, end)) spans.push({ start, end, kind: "name" });
    }
    return spans;
  }

  function tokenizeIdentities(text, watchlistRaw, registry) {
    const entries = collectEntries(text, watchlistRaw);
    if (!entries.size) return { text, identities: [] };
    const re = identityRegex(entries);
    const tally = new Map();

    const out = text.replace(re, (match, offset) => {
      if (!atWordEdge(text, offset, offset + match.length)) return match;
      const entry = entries.get(match.toLowerCase());
      const token = registry.tokenFor(entry.term, entry.category, entry.forced);
      const row = tally.get(entry.term) || { term: entry.term, token, category: entry.category, count: 0, first: offset };
      row.count++;
      tally.set(entry.term, row);
      return matchCase(token, match);
    });

    return { text: out, identities: [...tally.values()].sort((a, b) => a.first - b.first) };
  }

  function buildPrompt(code, identities, findings) {
    const classes = [...new Set(findings.map((f) => f.label))];
    const tokens = [...new Set(identities.map((i) => i.token))];
    const hits = identities.reduce((n, i) => n + i.count, 0);

    return [
      "ROLE",
      "You are a senior application-security engineer reviewing a codebase after a credential exposure.",
      "",
      "ABOUT THIS INPUT",
      "The code below was scrubbed locally before sharing. It contains no live credentials, internal hostnames, or proprietary names.",
      "",
      "RULES",
      "1. Secrets appear as placeholders like [REDACTED_JWT_01]. The same placeholder always means the same value.",
      `2. Proprietary names appear as synthetic tokens${tokens.length ? ` (${tokens.join(", ")})` : ""}. Treat them as opaque and consistent.`,
      "3. Keep every placeholder and token exactly as written in any code you produce.",
      "4. Do not ask for the original values or for the mapping.",
      "",
      "WHAT WAS REMOVED",
      `- ${findings.length} secret or random-looking values${classes.length ? `: ${classes.join(", ")}` : ""}.`,
      `- ${identities.length} names replaced across ${hits} occurrences.`,
      "",
      "TASK",
      "1. Give the most likely root cause in three sentences or fewer.",
      "2. Rewrite each placeholder location to read from environment variables or a secret manager, keeping interfaces unchanged.",
      "3. Point out other exposure the redaction may hide: logs, error reports, client-side bundles.",
      "4. Give a prioritized patch plan with concrete code changes.",
      "5. List what you cannot assess without the original values.",
      "",
      "FORMAT",
      "Markdown: summary first, then patches, then a follow-up checklist. Do not present guesses as facts.",
      "",
      "CODE",
      "~~~",
      code,
      "~~~"
    ].join("\n");
  }

  const api = { scan, IdentityRegistry, LIMITS, countLines, byteLength, formatBytes };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ZeroLeakEngine = api;
})(globalThis);
