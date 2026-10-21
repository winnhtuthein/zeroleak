# Changelog

All notable changes to ZeroLeak are listed here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org). The same history is published as `changelog.html`.

Changes to the legal documents (`privacy.html`, `terms.html`, `disclaimer.html`, `licenses.html`) are listed
here too; each of those pages also carries its own version history.

## [1.1.0] - 2026-10-21

### Added

- Legal pages: Privacy Policy, Terms of Use, Disclaimer and License, each with its own version number, effective date and version history.
- Page-view analytics through Vercel Web Analytics, loaded by a separate `analytics.js`. It is cookieless, page views only, and off for Do Not Track, Global Privacy Control, local files and localhost.
- This changelog, plus `CHANGELOG.md` in the project.
- `vercel.json` with security headers and clean URLs, and `/.well-known/security.txt`.
- Automated site checks (`tests/site.test.js`) covering links, version consistency, the content security policy, and that the scanning code makes no network calls.

### Changed

- The page's content security policy now allows same-origin requests (previously none) so analytics can work. Remote scripts, images, fonts, frames and form posts remain blocked.
- The badge now reads "Your code never leaves this tab" instead of "0 requests sent", because the page may now send an anonymous page view. It still turns red if the browser blocks a request.
- Footer links to the legal pages and the current version.

## [1.0.0] - 2026-10-19

### Added

- First release: in-browser scanner for secrets and company names, with highlighted input, redacted output on a paper sheet, AI prompt tab, watchlist, entropy controls, copy and export.
