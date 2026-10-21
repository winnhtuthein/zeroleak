# Security

ZeroLeak is a best-effort tool and cannot guarantee that every secret is found. Treat its output as a first pass and review it before sharing.

To report a vulnerability, such as a way for data to leave the page or a detector bypass that hides a real secret, please open a private security advisory on the repository, or an issue if advisories are unavailable. Do not include real credentials in reports; use fake ones.

## What counts

- Any way for pasted text to leave the page (a network request carrying it, storage, logging).
- A detector bypass that hides a real secret from the output.
- Weaknesses in the site's headers or content security policy.

Analytics (`analytics.js`) is the one intentional network request; it sends page views only and never page content. A way to make it read or send editor contents is a vulnerability.

## What to expect

This is a one-person project, so there is no formal SLA. I aim to acknowledge reports within 7 days. Please allow a reasonable time to fix before disclosing publicly, and I will credit you if you want. Good-faith research that follows this policy and avoids harming other people's data or the hosted service will not be met with legal action. The contact is also in `.well-known/security.txt`.
