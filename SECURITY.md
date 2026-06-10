# 🔒 Security Policy

First of all — **thank you** for taking the time to look into the security of Starpass. Responsible disclosure makes the open-source world safer for everyone, and we genuinely appreciate your effort.

---

## Our Philosophy

Starpass is built around a **zero-knowledge, privacy-first** architecture. Every credential is generated locally in your browser — nothing is ever sent to a server, stored in a database, or shared with third parties. That said, the client-side code itself must be trustworthy, so we take security reports very seriously.

---

## Supported Versions

We only maintain the **latest release** on the `main` branch. Please make sure you're testing against the most recent version before filing a report.

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ Yes |
| Older commits | ❌ No — please update first |

---

## What Counts as a Security Issue?

Here are examples of things we'd consider genuine security vulnerabilities:

- **Cryptographic weaknesses** — flaws in how `crypto.getRandomValues()` is used that could make generated credentials predictable.
- **Cross-Site Scripting (XSS)** — any way to inject and execute arbitrary scripts through the UI.
- **Content Security Policy (CSP) bypass** — tricks that circumvent the declared CSP headers.
- **Dependency vulnerabilities** — critical CVEs in `zxcvbn` or any other bundled library.
- **Clipboard hijacking** — scenarios where clipboard content could be intercepted or exfiltrated.
- **PWA / Service Worker abuse** — exploitable misconfiguration of the service worker or caching layer.
- **Privacy leaks** — any unintentional transmission of user input, generated credentials, or metadata to a remote server.

Things that are **out of scope** (please don't report these as security bugs):

- Theoretical attacks that require physical access to the user's already-unlocked device.
- Browser-level bugs that are the browser vendor's responsibility to fix.
- Spam, social engineering, or phishing targeting Starpass users (report these to the relevant platform instead).
- Issues that only affect browsers that are officially end-of-life.

---

## How to Report a Vulnerability

> [!CAUTION]
> **Do NOT open a public GitHub Issue for security vulnerabilities.** Public issues are visible to everyone, which could put users at risk before a fix is available.

Please report vulnerabilities **privately** using one of these channels:

1. **GitHub Private Security Advisory (preferred)**
   Go to the [Security tab → "Report a vulnerability"](https://github.com/Samin-yasar/Starpass/security/advisories/new) on the repository. GitHub keeps this completely private between you and the maintainer.

2. **Email**
   Send your report to **[contact@samin-yasar.dev](mailto:contact@samin-yasar.dev)** with the subject line:
   ```
   [STARPASS SECURITY] Brief description of the issue
   ```

### What to Include in Your Report

The more detail you provide, the faster we can triage and fix the issue. Please include:

- **Description** — a clear summary of the vulnerability and what an attacker could do with it.
- **Steps to reproduce** — a minimal, step-by-step walkthrough to trigger the bug.
- **Affected component** — which file(s) or feature(s) are involved (e.g., `app.js`, passphrase generator, clipboard button).
- **Potential impact** — your assessment of severity (data leak? credential exposure? XSS?).
- **Suggested fix** *(optional but appreciated)* — if you have an idea for how to fix it.
- **Proof of concept** *(optional)* — a screenshot, screen recording, or minimal code snippet.

---

## Response Timeline

We are a small, solo-maintained open-source project, but we take security seriously. Here is what you can expect:

| Milestone | Target Timeframe |
|-----------|-----------------|
| Acknowledgement of your report | Within **72 hours** |
| Triage and initial assessment | Within **7 days** |
| Fix development & testing | Within **30 days** (complex issues may take longer) |
| Public disclosure | After a fix is released, coordinated with you |

We will keep you updated throughout the process. If you haven't heard back within 72 hours, please follow up — your message may have landed in spam.

---

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. You report the vulnerability privately.
2. We confirm the issue and work on a fix.
3. We release a patched version.
4. We publish a GitHub Security Advisory crediting you (unless you prefer to remain anonymous).
5. You are welcome to publish your own writeup after the advisory is public.

We ask that you give us a **reasonable window** (typically 30 days, extendable by mutual agreement) before any public disclosure.

---

## Recognition

We don't have a bug bounty program (Starpass is a not-for-profit project), but we will:

- Credit you in the Security Advisory and release notes.
- Add your name to our **Hall of Thanks** in this file if you wish.

Thank you for helping keep Starpass safe. 🙏

---

*Last updated: June 2026*
