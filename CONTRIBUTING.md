# Contributing

Thanks for helping improve ZeroLeak.

## Before you open a pull request

- Run `npm test` (Node 18 or newer). All tests must pass.
- New detectors need a test in `tests/engine.test.js`, including one case that should **not** be flagged.
- Check a new detector for false positives with `node scripts/corpus-scan.js <folder-of-real-code> 5`. It prints a few matches per class.
- Keep the app dependency-free and offline. No external scripts, fonts, images or network calls.
- Never put real credentials in code, tests or issues. Use obviously fake ones.

## License of your contribution

ZeroLeak is licensed under AGPL-3.0-or-later. By submitting a contribution you confirm that you wrote it, or have the right to submit it, and you agree it is licensed under the same terms. Sign off each commit to confirm this (the [Developer Certificate of Origin](https://developercertificate.org/)):

```
git commit -s -m "Add detector for ..."
```

Contributors keep the copyright in their own contributions.

## Reporting security problems

See `SECURITY.md`.
