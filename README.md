# ZeroLeak

You paste code into an AI chat to get help, and the code has a database password in it. ZeroLeak is a page that catches that before you hit send.

Paste code on the left; whatever it finds is shaded there (red for secrets, yellow for names) so you can see exactly what it caught. On the right you get the same code on a "paper" page: secrets are blacked out as `[REDACTED_JWT_01]`, and project or company names you listed are swapped for neutral ones like `ProjectAlpha` and highlighted in yellow. Copy the result, or copy the **AI prompt** tab, which wraps it in instructions for the assistant.

It's one static page. No server, no account, no install, no build. Your code stays in the tab.

The hosted site also counts anonymous page views (see [Analytics](#analytics-and-legal-pages)). That never includes your code.

## Run it

Put `index.html`, `styles.css`, `engine.js`, `app.js` and `analytics.js` in one folder and open `index.html`. Hit **Try a sample** to see it work.

## What it catches

- Keys and tokens with a known shape (30+ patterns): private keys, AWS, Azure, Stripe, GitHub, GitLab, Google, Slack, Discord, Telegram, Twilio, SendGrid, Shopify, DigitalOcean, Databricks, Hugging Face, npm, PyPI, Anthropic, OpenAI-style keys, JWTs, bearer and basic-auth headers, webhook URLs
- Passwords embedded in URLs, database connection strings, and internal hostnames (`.internal`, `.local`, `.corp`)
- Things assigned to names like `password`, `apiKey`, `secret`, including JSON and TypeScript forms, and `.env` lines
- Quoted strings that look random, using Shannon entropy (the sliders tune it)
- Names from the watchlist, matched in any case and inside `camelCase` and `SNAKE_CASE`

Identical secrets share one placeholder; different ones never do. Nothing in a placeholder is derived from the secret.

## Read this before trusting it

It's a first pass, not a guarantee. **Read the output before you share it.**

If a real secret was ever pasted somewhere it shouldn't have been, redacting it now doesn't help. Rotate it.

How well it does, measured:

- **False positives.** Running it over about 250 MB of real public code (npm and Python packages) first flagged thousands of harmless strings: integrity hashes, identifiers like `bearerTokenAuthenticationPolicy`, AWS's documented `...EXAMPLE` keys. Those are now filtered. What's left is around one flag per 0.5 MB, mostly embedded base64 data. The new vendor patterns produced no false positives there. `scripts/corpus-scan.js` repeats this on any folder.
- **Misses.** The vendor patterns are tested against fake keys built to each vendor's documented format, not against live keys. Whether it misses secrets in *your* code is something only your code can show. Please try it on an old project and open an issue with what slips through (using fake values).

Known gaps:

- Real scanners like gitleaks and trufflehog know hundreds of formats. This knows about 30. If you need a service covered, add a detector.
- A secret with no known format and no telling variable name (a short password in a comment, say) gets through.
- The filters that cut false positives also drop a few real cases: a password that is a plain sentence or passphrase with spaces, or an all-caps single word.
- Random strings longer than 160 characters are treated as data, not tokens (long keys have their own patterns).
- Auto-detected company names sometimes swallow a leading word ("Owner Vantage Systems Inc"). The watchlist is the reliable way.
- Variables named only `KEY` or `TOKEN` with short values are ignored on purpose.
- Over 1.5 MB it only scans when you press **Sanitize**. Over 12 MB it refuses. Highlighting stops above 400 KB.
- Tested in Chromium (two versions). Not yet tested in Firefox or Safari.

## How the "local" claim works

`index.html` carries a Content Security Policy that tells the browser to refuse remote scripts, images, fonts, frames and form posts, and to allow only requests back to the same site. That is enforced by the browser, not by this code. On top of that, `engine.js` and `app.js` contain no network calls, and `npm test` fails if one is added. The sandbox badge counts the violations the browser reports, so it only turns red if something actually got blocked. Nothing is saved; closing the tab clears it. Exports are text files written to your own disk.

If you load the page from a web host, remember the host serves the page. Download it and open it from disk if that matters to you; analytics does not run from disk.

## Analytics and legal pages

When deployed on Vercel, `analytics.js` loads [Vercel Web Analytics](https://vercel.com/docs/analytics/privacy-policy) (cookieless, page views only). It is skipped on Do Not Track, Global Privacy Control, `file:` and localhost. It is a plain-HTML setup: the `@vercel/analytics` npm package is for bundled frameworks and is not needed here. To use it, enable Analytics for the project in the Vercel dashboard and redeploy. To remove it, delete the `analytics.js` script tags (and set `connect-src 'none'` in `index.html` to restore the original lock).

The site ships `privacy.html`, `terms.html`, `disclaimer.html`, `licenses.html` and `changelog.html`, each versioned with its own history. Before going live, replace the placeholders any `{{PLACEHOLDER}}` tokens; `npm run check` lists any left. Have a lawyer review the legal pages for your situation.

## Development

`engine.js` is the scanner (no DOM). `app.js` is the interface. `analytics.js` is the optional analytics loader. Node 18+:

```
npm test
```

A new detector needs a test, including one string it should leave alone. More in `CONTRIBUTING.md`.

## License

Copyright (C) 2026 Winn Htut Hein. Licensed under **AGPL-3.0-or-later** (see `LICENSE`).

Short version: use it, change it, sell it, but if you distribute it or run a modified copy as a service, you publish your source under the same license and keep the copyright notices. There's no warranty.

The name "ZeroLeak" and the logo are not covered by the license; see `NOTICE`. Logo files and a brand sheet are in `assets/logo/`. For closed-source use, contact the author about a commercial license.
