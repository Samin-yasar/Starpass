# 🤝 Contributing to Starpass

Welcome, and thank you for your interest in contributing to **Starpass Generator**! Whether you're fixing a typo, improving accessibility, squashing a bug, or proposing a brand-new feature — every contribution matters to us.

Starpass is a **not-for-profit, open-source** project built around one core belief: everyone deserves strong, private credential generation without giving up their data. Your contributions help make that vision real for more people.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Questions?](#questions)

---

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to uphold it. Please report unacceptable behaviour to **[contact@samin-yasar.dev](mailto:contact@samin-yasar.dev)**.

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Found something broken? Before opening an issue, please:

1. **Check existing issues** — it may already be reported or fixed in `main`.
2. **Reproduce it** — confirm the bug exists in the latest version.
3. **Open an Issue** using the **Bug Report** template. Fill in every section — the more detail you provide, the faster we can fix it.

### 💡 Suggesting Features

Have an idea that aligns with Starpass's privacy-first mission? We'd love to hear it.

1. **Search existing issues** for similar suggestions — add a 👍 reaction to show support instead of filing a duplicate.
2. **Open an Issue** using the **Feature Request** template and describe your idea clearly.

### 📖 Improving Documentation

Spotted a typo, a confusing sentence, or a missing explanation? Documentation PRs are always welcome and a great way to get started.

### 🔐 Security Issues

> [!CAUTION]
> **Do NOT open a public issue for security vulnerabilities.** Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### 🌍 Translations & Accessibility

Starpass aims to be usable by everyone. Improvements to accessibility (ARIA, contrast, keyboard navigation) or help translating the UI are highly valued.

---

## Before You Start

For **non-trivial changes** (new features, significant refactors), please **open an issue first** and describe what you want to do. This prevents you from investing time in a PR that might not align with the project's direction, and gives us a chance to discuss the design together.

For small fixes (typos, broken links, minor CSS tweaks), feel free to go straight to a PR.

---

## Development Setup

Starpass is a pure browser-based app — no build system required.

```bash
# 1. Fork the repository on GitHub, then clone your fork:
git clone https://github.com/YOUR_USERNAME/Starpass.git
cd Starpass

# 2. (Optional) Install zxcvbn if you need to update the dependency:
npm install zxcvbn

# 3. Serve the app locally:
python -m http.server 8000
# or: npx serve .

# 4. Open http://localhost:8000 in your browser.
```

> **Note:** There is no transpilation or bundling step. All source files are plain HTML, CSS, and JavaScript. Edits are immediately reflected on page refresh.

---

## Making Changes

1. **Create a branch** from `main` with a descriptive name:
   ```bash
   git checkout -b fix/clipboard-issue
   git checkout -b feature/strength-meter-ui
   git checkout -b docs/update-readme
   ```

2. **Make your changes.** Keep commits small and focused — one logical change per commit.

3. **Write a clear commit message:**
   ```
   type: short summary in present tense

   Optional longer description explaining the why.
   ```
   Common types: `fix`, `feat`, `docs`, `style`, `refactor`, `test`, `chore`.

4. **Test manually** — open the app in at least one modern browser (Chrome, Firefox, or Edge) and verify your changes work as expected and don't break anything else.

5. **Push your branch** to your fork:
   ```bash
   git push origin fix/clipboard-issue
   ```

---

## Pull Request Process

1. Open a Pull Request from your fork to `Samin-yasar/Starpass`'s `main` branch.
2. Use the **PR template** — fill in all sections (summary, what changed, how to test, checklist).
3. Link any related issues using GitHub keywords (e.g., `Closes #42`).
4. A maintainer will review your PR and may leave feedback. Please respond to comments in a timely manner.
5. Once approved, we'll merge it. 🎉

**PR requirements:**

- [ ] Changes are scoped — one feature or fix per PR.
- [ ] Manual testing has been done.
- [ ] No new external dependencies are introduced without prior discussion.
- [ ] Code follows the project's style conventions (see below).
- [ ] No credentials, API keys, or personal data are included.
- [ ] License compatibility: all contributed code must be compatible with **GPLv3**.

---

## Style Guide

Starpass has no linter configuration yet, but please follow these conventions:

### JavaScript
- Use `const` and `let` — never `var`.
- Prefer descriptive variable names over single letters (except loop counters).
- Use `crypto.getRandomValues()` for all randomness — **never** `Math.random()` for security-sensitive operations.
- Add a brief comment above functions explaining what they do and why.

### HTML
- Use semantic elements (`<main>`, `<section>`, `<button>`, etc.) instead of generic `<div>` soup.
- Every interactive element must have an accessible label (`aria-label` or visible `<label>`).

### CSS
- Variables are defined in `:root` inside `style.css`. Use them — don't hardcode colours.
- Keep selectors specific enough to be readable but avoid overly deep nesting.

### General
- No trailing whitespace.
- Files should end with a single newline character.
- Keep lines reasonably short (soft limit: 120 characters).

---

## Security Vulnerabilities

If you discover a security issue while contributing, please **do not** include it in a PR or public issue. Instead, follow the process outlined in [SECURITY.md](SECURITY.md).

---

## Questions?

If you're unsure about anything, just ask! You can:

- Open a [GitHub Discussion](https://github.com/Samin-yasar/Starpass/discussions) (if enabled).
- Reach out via **[contact@samin-yasar.dev](mailto:contact@samin-yasar.dev)**.

We'd rather answer a question than have a great contribution never get submitted. Happy coding! 🚀

---

*Starpass is maintained by [Samin Yasar](https://samin-yasar.dev/) and licensed under [GPLv3](LICENSE).*
