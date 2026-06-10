# ⭐ Starpass Generator

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Code%20of%20Conduct-Contributor%20Covenant-blueviolet.svg)](CODE_OF_CONDUCT.md)
[![PWA Ready](https://img.shields.io/badge/PWA-Ready-5A0FC8.svg)](#installing-as-a-pwa)

**Starpass Generator** is a **not-for-profit, open-source** web application that generates secure passwords, passphrases, and usernames — entirely in your browser. Built on a **zero-knowledge architecture**, Starpass never collects, stores, or transmits your data. It works offline as a Progressive Web App (PWA) and is licensed under the [GNU General Public License Version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0).

Starpass uses the [**zxcvbn**](https://github.com/dropbox/zxcvbn) library for password strength assessment and a structured local word dataset (`src/common_wordslist.json`) for passphrase and username generation. The dataset is organized by word length and semantic roles (adjectives, nouns, verbs) to produce readable, high-quality output.

> **Beta notice:** Starpass is actively developed. Some features are still in progress — expect occasional rough edges and check the [Roadmap](#roadmap) for what's coming.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Privacy and Data Handling](#privacy-and-data-handling)
- [Technical Details](#technical-details)
- [Security](#security)
- [Contributing](#contributing)
- [Community](#community)
- [Roadmap](#roadmap)
- [License](#license)
- [Support](#support)
- [Acknowledgments](#acknowledgments)

---

## Features

| Feature | Description |
|---------|-------------|
| 🔑 **Password Generator** | Adjustable length, character sets (lower, upper, numbers, symbols), and optional ambiguous-character exclusion |
| 🗣️ **Passphrase Generator** | Role-based word combinations, customisable word count, separator choice, capitalisation, and number/symbol appending |
| 👤 **Username Generator** | Length-aware, role-templated combinations (e.g. adjective+noun) with case and number options |
| 🛡️ **Strength Analysis** | Real-time zxcvbn scoring (0–4) with crack-time estimate and improvement suggestions |
| 🔒 **Zero-Knowledge** | All processing happens locally — no cookies, no trackers, no analytics, no server calls |
| 📱 **PWA / Offline** | Install from Chrome or Edge for full offline access |
| ♿ **Accessibility** | Standard and high-contrast themes; keyboard-navigable interface |
| 📋 **Clipboard Copy** | One-click copy with visual confirmation |

---

## Installation

Starpass is a pure browser app — no build step required.

### Using Online

Visit **[https://starpass.samin-yasar.dev](https://starpass.samin-yasar.dev)** — no account or installation needed.

### Installing as a PWA

1. Open Starpass in Chrome or Edge.
2. Click the **Install** icon in the address bar (or choose *"Add to Home Screen"* on mobile).
3. Launch Starpass any time from your app menu or home screen, fully offline.

### Running Locally

```bash
# 1. Clone the repository
git clone https://github.com/Samin-yasar/Starpass.git
cd Starpass

# 2. Serve with any static file server
python -m http.server 8000
# or: npx serve .

# 3. Open in your browser
open http://localhost:8000
```

> **Note:** `zxcvbn` is already bundled at `src/zxcvbn.min.js` — no `npm install` is required to run the app. If you want to update the library, run `npm install zxcvbn` and replace the bundled file.

---

## Usage

### 🔑 Generate a Password

1. Open the **Password** tab.
2. Set the desired length (default: 16) and select character types.
3. Optionally enable *Exclude Ambiguous Characters* to avoid look-alike characters like `l`, `I`, `0`, `O`.
4. Click **Generate Password**.

### 🗣️ Generate a Passphrase

1. Open the **Passphrase** tab.
2. Choose word count and separator (hyphen, dot, underscore, space, or none).
3. Optionally enable capitalisation or append a number/symbol.
4. Click **Generate Passphrase**.

### 👤 Generate a Username

1. Open the **Username** tab.
2. Set target length and choose a role template.
3. Optionally force lowercase or append a number.
4. Click **Generate Username**.

### 📋 Copy & Use

- Click the **Copy to Clipboard** button next to any result.
- The strength meter beneath each result shows the zxcvbn score and estimated crack time.

### 🎨 Toggle Theme

Use the theme toggle in the top-right corner to switch between standard and high-contrast modes.

---

## Privacy and Data Handling

Starpass is built around one core principle: **your credentials never leave your device.**

- ✅ All generation and processing happen locally in your browser.
- ✅ No personal data (credentials, IP address, browser fingerprint) is collected, stored, or transmitted.
- ✅ No cookies, trackers, or analytics are used.
- ✅ The app works fully offline — it never needs a network connection after the initial load.
- ✅ Support requests sent via email are the only case where you voluntarily share data, and that data is retained minimally.

For full details, see the [Privacy Notice](policy/privacy-notice.html).

---

## Technical Details

### Password Strength Assessment

Starpass integrates [zxcvbn](https://github.com/dropbox/zxcvbn) (MIT-licensed, by Dropbox) for realistic strength estimation. zxcvbn evaluates passwords against common patterns — dictionary words, keyboard sequences, date formats, repetitions — and returns a score from 0 (very weak) to 4 (very strong) along with estimated crack time and actionable suggestions.

### Word Dataset

`src/common_wordslist.json` is organised into multiple layers:

- **Length buckets** — words grouped by character count (3 through 11 characters) for length-aware generation.
- **Semantic categories** — adjectives, nouns, verbs, and connectors for meaningful word combinations.
- **Role templates** — pre-defined patterns (e.g. `adjective+noun`, `noun+verb+noun`) that produce coherent passphrases and readable usernames.

### Randomness

All credential generation uses `crypto.getRandomValues()` (the Web Cryptography API) — never `Math.random()`. This ensures cryptographically secure randomness in all modern browsers.

---

## Security

Security is a first-class concern in Starpass. If you discover a vulnerability, please **do not open a public GitHub issue** — that could put users at risk before a fix is ready.

Instead, please report privately:

- 🔒 **[GitHub Private Security Advisory](https://github.com/Samin-yasar/Starpass/security/advisories/new)** *(preferred)*
- 📧 **[contact@samin-yasar.dev](mailto:contact@samin-yasar.dev)** with subject `[STARPASS SECURITY] …`

Read the full disclosure process, scope, and response timeline in **[SECURITY.md](SECURITY.md)**.

---

## Contributing

Starpass is open-source and community-driven — contributions of all kinds are welcome.

- 🐛 **Found a bug?** → [Open a Bug Report](https://github.com/Samin-yasar/Starpass/issues/new?template=bug_report.yml)
- 💡 **Have a feature idea?** → [Submit a Feature Request](https://github.com/Samin-yasar/Starpass/issues/new?template=feature_request.yml)
- 📖 **Spotted a docs issue?** → [Report a Documentation Issue](https://github.com/Samin-yasar/Starpass/issues/new?template=documentation.yml)
- ✨ **Want to write code?** → Read **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full workflow, branch conventions, style guide, and PR checklist.

**Quick start for contributors:**

```bash
git clone https://github.com/YOUR_USERNAME/Starpass.git
cd Starpass
python -m http.server 8000   # no build step needed
```

All contributions must be compatible with **GPLv3**. Please use `crypto.getRandomValues()` for any security-sensitive randomness — never `Math.random()`.

---

## Community

We are committed to building an open, welcoming, and harassment-free community.

| Document | Purpose |
|----------|---------|
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Standards for participation and enforcement process |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute code, docs, and ideas |
| [SECURITY.md](SECURITY.md) | How to responsibly disclose security vulnerabilities |
| [SUPPORT.md](SUPPORT.md) | Where to get help and expected response times |

### Automated Issue & PR Templates

When you open a new issue or pull request on GitHub, you'll be guided by structured forms that ensure clear, actionable reports:

- **Bug Report** — prompts for affected feature, steps to reproduce, browser, OS, and console errors.
- **Feature Request** — frames requests around *problems* before solutions, with priority level.
- **Documentation Issue** — file location picker and issue type dropdown.
- **Pull Request** — type-of-change checklist, testing steps, browser matrix, security checklist, and breaking-change declaration.

Blank issues are disabled — every report follows a template, so nothing important gets missed.

---

## Roadmap

- [ ] Complete real-time strength analysis display (zxcvbn integration).
- [ ] Implement **Save to History** with local, encrypted storage.
- [ ] Add integration with **StarryCrypt**.
- [ ] Enhance PWA stability and cross-browser compatibility.
- [ ] Expand accessibility options (ARIA, keyboard navigation, screen reader support).
- [ ] Internationalisation (i18n) support.

---

## License

Starpass Generator is licensed under the **[GNU General Public License Version 3 (GPLv3)](LICENSE)**. You are free to use, modify, and distribute the code, provided that any derivative work is also distributed under GPLv3 with its source code available.

The bundled [zxcvbn](https://github.com/dropbox/zxcvbn) library is MIT-licensed by Dropbox, Inc.

---

## Support

| I need help with… | Go to… |
|--------------------|--------|
| A bug or broken feature | [GitHub Issues → Bug Report](https://github.com/Samin-yasar/Starpass/issues/new?template=bug_report.yml) |
| A feature suggestion | [GitHub Issues → Feature Request](https://github.com/Samin-yasar/Starpass/issues/new?template=feature_request.yml) |
| A security vulnerability | [SECURITY.md](SECURITY.md) — report privately |
| General questions | [contact@samin-yasar.dev](mailto:contact@samin-yasar.dev) or [samin-yasar.dev/#contact](https://samin-yasar.dev/#contact) |

For full details and expected response times, see **[SUPPORT.md](SUPPORT.md)**.

---

## Acknowledgments

Developed by [Samin Yasar](https://samin-yasar.dev/) as a community-driven, not-for-profit project.

Special thanks to:

- [Dropbox](https://github.com/dropbox/zxcvbn) — for the zxcvbn password strength library (MIT licence).
- [Electronic Frontier Foundation (EFF)](https://www.eff.org) — for the Long Wordlist that informed our word dataset.
- All contributors and the broader open-source community for supporting privacy-respecting tools.

---

*Made with ❤️ for a more private internet.*
