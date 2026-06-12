# Starpass — Phase 3: Connected Keys / PGP Sub-Tab
## Architectural Specification & Implementation Blueprint

> **Document Status:** `PRODUCTION-READY BLUEPRINT`
> **Phase:** 3 — Connected Keys / PGP Sub-Tab
> **Authored by:** Asynchronous Cryptographic Architect (AI Agent)
> **Target Lead Developer:** _(Returning from academic preparation)_
> **Last Updated:** 2026-06-11
> **Confidentiality:** Internal Engineering — Do Not Distribute

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Constraints](#2-scope--constraints)
3. [Architectural Overview](#3-architectural-overview)
4. [Layer 1 — Frontend Layout & UI Component Specification](#4-layer-1--frontend-layout--ui-component-specification)
5. [Layer 2 — Client-Side Cryptographic Web Worker](#5-layer-2--client-side-cryptographic-web-worker)
6. [Layer 3 — Vault Interoperability & IndexedDB Storage Schema](#6-layer-3--vault-interoperability--indexeddb-storage-schema)
7. [Layer 4 — Serverless Keyserver Integration (HKP/VKS)](#7-layer-4--serverless-keyserver-integration-hkpvks)
8. [Layer 5 — User Safety Advisory & Disclosure Framework](#8-layer-5--user-safety-advisory--disclosure-framework)
9. [Security Threat Model & Mitigations](#9-security-threat-model--mitigations)
10. [Dependency Manifest](#10-dependency-manifest)
11. [Testing Strategy](#11-testing-strategy)
12. [Implementation Checklist](#12-implementation-checklist)

---

## 1. Executive Summary

Phase 3 extends Starpass with a full-featured **PGP Key Management sub-tab** ("Keys") integrated into the existing generator tab-bar alongside Password, Passphrase, and Username. This phase introduces:

- **In-browser asymmetric key pair generation** (ECC Curve25519 or RSA 4096) executed entirely inside a **Web Worker** to preserve main-thread responsiveness.
- **Encrypted local persistence** of both public and private key material inside the existing IndexedDB vault using the project's established AES-256-GCM derivation pipeline.
- **Optional one-click publishing** of the user's public key to the global OpenPGP keyserver network (`keys.openpgp.org`) via the VKS HTTP API — with explicit informed-consent warnings about the permanent, public, and irrevocable nature of keyserver publication.

**This document is the single source of truth for implementation.** No production code is modified by this document; it describes what must be built.

---

## 2. Scope & Constraints

### 2.1 In Scope

| Item | Notes |
|------|-------|
| 4th tab button ("Keys") in tab-bar | UI placement only; no existing tab behavior changes |
| PGP key generation UI form | Name, Email, Algorithm toggle, local passphrase, publish toggle |
| `pgp.worker.js` Web Worker module | Offloads openpgp.js computation |
| IndexedDB schema extension | New `pgpKeys` store within existing encrypted vault |
| VKS API integration | `POST https://keys.openpgp.org/vks/v1/upload` |
| User safety disclosure UI | Modal + inline warnings |
| Error handling pipelines | Worker errors, network errors, validation errors |

### 2.2 Out of Scope

| Item | Reason |
|------|--------|
| Key signing / Web of Trust UI | Phase 4 concern |
| Key revocation certificates | Phase 4 concern |
| In-app PGP encryption/decryption of messages | Phase 5 concern |
| GnuPG CLI interoperability | Out of browser scope |
| Subkey management | Phase 4 concern |
| Multi-device key sync | Requires server infrastructure (Phase 6) |

### 2.3 Hard Technical Constraints

- **Zero server-side processing.** All cryptographic operations occur in the browser.
- **No plaintext private key material ever touches `localStorage` or the network.**
- **openpgp.js must run inside a Web Worker.** It must never block the UI thread.
- **The existing AES-256-GCM vault pipeline must not be duplicated or replaced** — it must be reused for PGP private key encryption at rest.
- **CORS:** The only external network call permitted is the VKS upload (`keys.openpgp.org`), and only when the user has explicitly opted in and confirmed the safety disclosure.

---

## 3. Architectural Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MAIN UI THREAD                                 │
│                                                                         │
│  ┌──────────┬─────────────┬──────────┬─────────────────────────────┐   │
│  │ Password │  Passphrase │ Username │  🔑 Keys  ← NEW TAB (Phase 3)│   │
│  └──────────┴─────────────┴──────────┴─────────────────────────────┘   │
│                                         │                               │
│                              ┌──────────▼──────────────┐               │
│                              │   KeysTab Component      │               │
│                              │  ┌─────────────────────┐│               │
│                              │  │  IdentityForm        ││               │
│                              │  │  AlgorithmToggle     ││               │
│                              │  │  PassphraseInput     ││               │
│                              │  │  PublishToggle       ││               │
│                              │  │  GenerateButton      ││               │
│                              │  └─────────────────────┘│               │
│                              └──────────┬───────────────┘               │
│                                         │ postMessage(generateRequest)  │
│                     ┌───────────────────▼─────────────────────┐        │
│                     │          WEB WORKER BOUNDARY             │        │
│                     │  ┌────────────────────────────────────┐ │        │
│                     │  │         pgp.worker.js              │ │        │
│                     │  │  import * as openpgp from 'openpgp'│ │        │
│                     │  │  openpgp.generateKey(config)       │ │        │
│                     │  │  → { publicKey, privateKey,        │ │        │
│                     │  │      revocationCertificate }       │ │        │
│                     │  └────────────────────────────────────┘ │        │
│                     └───────────────────┬─────────────────────┘        │
│                                         │ postMessage(keyMaterial)      │
│                                         ▼                               │
│                         ┌───────────────────────────┐                  │
│                         │    VaultService            │                  │
│                         │  encryptPrivateKey(        │                  │
│                         │    privateKeyArmored,      │                  │
│                         │    vaultMasterKey          │                  │
│                         │  ) → AES-256-GCM ciphertext│                  │
│                         └──────────────┬────────────┘                  │
│                                        │                                │
│                    ┌───────────────────▼────────────────┐              │
│                    │         IndexedDB Vault             │              │
│                    │  store: "pgpKeys"                   │              │
│                    │  { id, fingerprint, publicKey,      │              │
│                    │    encryptedPrivateKey, identity,   │              │
│                    │    algorithm, createdAt, published } │              │
│                    └───────────────────┬────────────────┘              │
│                                        │ (if publishToggle = true)      │
│                    ┌───────────────────▼────────────────┐              │
│                    │    KeyserverService                 │              │
│                    │  POST /vks/v1/upload                │              │
│                    │  keys.openpgp.org                   │              │
│                    │  { keytext: armoredPublicKey }      │              │
│                    └────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Layer 1 — Frontend Layout & UI Component Specification

### 4.1 Tab-Bar Extension

The existing tab-bar renders three tab buttons. A 4th tab must be appended with zero changes to the existing three tabs' rendering logic.

**Tab Button Specification:**

```html
<!-- Insert as 4th child of the tab-bar container. 
     Apply the same CSS class pattern as existing tabs. -->
<button
  class="tab-btn"
  id="tab-keys"
  role="tab"
  aria-selected="false"
  aria-controls="panel-keys"
  tabindex="-1"
  data-tab="keys"
>
  <!-- Icon: use an SVG key icon at 16×16 or project's icon library equivalent -->
  <svg aria-hidden="true" focusable="false" width="16" height="16" viewBox="0 0 24 24">
    <path d="M12.65 10A6 6 0 1 0 10 12.65L19.35 22 22 19.35l-1.65-1.65L22 16l-1.65-1.65
             L22 12.69 19.31 10H12.65zM7 11a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"
          fill="currentColor"/>
  </svg>
  <span>Keys</span>
</button>
```

**Accessibility Requirements:**

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `role="tab"` | static | ARIA tab pattern |
| `aria-selected` | `"false"` / `"true"` | Toggled by tab controller |
| `aria-controls` | `"panel-keys"` | Links tab to its panel |
| `tabindex` | `-1` / `0` | Roving tabindex pattern |

---

### 4.2 Keys Panel — Full Component Specification

**Panel Container:**

```html
<section
  id="panel-keys"
  role="tabpanel"
  aria-labelledby="tab-keys"
  hidden
  class="tab-panel tab-panel--keys"
>
  <!-- All child components below are mounted here -->
</section>
```

---

### 4.3 Identity Form Group (Optional)

Both fields are **optional**. A PGP key can be generated without a User ID, but the keyserver requires at least one verified email address to publish a discoverable key.

```html
<fieldset class="form-group form-group--identity" aria-label="Key Identity (Optional)">
  <legend class="form-group__legend">
    Identity
    <span class="form-group__optional-badge" aria-label="optional">Optional</span>
  </legend>

  <!-- Name Field -->
  <div class="field-wrapper">
    <label for="pgp-name" class="field-label">
      Full Name
    </label>
    <input
      type="text"
      id="pgp-name"
      name="pgp-name"
      class="field-input"
      placeholder="e.g. Jane Doe"
      autocomplete="name"
      autocorrect="off"
      autocapitalize="words"
      spellcheck="false"
      maxlength="128"
      aria-describedby="pgp-name-hint"
    />
    <p id="pgp-name-hint" class="field-hint">
      Displayed alongside your public key on keyservers.
    </p>
  </div>

  <!-- Email Field -->
  <div class="field-wrapper">
    <label for="pgp-email" class="field-label">
      Email Address
    </label>
    <input
      type="email"
      id="pgp-email"
      name="pgp-email"
      class="field-input"
      placeholder="e.g. jane@example.com"
      autocomplete="email"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      maxlength="254"
      aria-describedby="pgp-email-hint pgp-email-error"
      aria-invalid="false"
    />
    <p id="pgp-email-hint" class="field-hint">
      Required only if publishing to a keyserver.
    </p>
    <!-- Error state: injected dynamically by validation logic -->
    <p id="pgp-email-error" class="field-error" role="alert" hidden></p>
  </div>
</fieldset>
```

**Email Validation Regex:**

```javascript
// RFC 5322 simplified — covers 99.9% of real-world addresses.
// Do NOT use this for security gating; it is UX feedback only.
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

/**
 * Validates email input and updates ARIA error state.
 * @param {string} value - Raw input value from the email field.
 * @returns {{ valid: boolean, message: string }}
 */
function validateEmail(value) {
  if (value.trim() === '') {
    return { valid: true, message: '' }; // Empty is OK — field is optional
  }
  if (!EMAIL_REGEX.test(value.trim())) {
    return {
      valid: false,
      message: 'Please enter a valid email address (e.g. jane@example.com).'
    };
  }
  return { valid: true, message: '' };
}
```

---

### 4.4 Algorithm Toggle

```html
<fieldset class="form-group form-group--algorithm" aria-label="Key Algorithm">
  <legend class="form-group__legend">Algorithm</legend>

  <div class="toggle-group" role="radiogroup" aria-label="Select key algorithm">

    <!-- Default: ECC Curve25519 -->
    <label class="toggle-option toggle-option--active">
      <input
        type="radio"
        name="pgp-algorithm"
        value="ecc"
        checked
        aria-describedby="algo-ecc-desc"
      />
      <span class="toggle-option__label">ECC Curve25519</span>
    </label>
    <p id="algo-ecc-desc" class="field-hint">
      Modern, fast, small keys. Recommended for most users.
    </p>

    <!-- Option: RSA 4096 -->
    <label class="toggle-option">
      <input
        type="radio"
        name="pgp-algorithm"
        value="rsa4096"
        aria-describedby="algo-rsa-desc"
      />
      <span class="toggle-option__label">RSA 4096</span>
    </label>
    <p id="algo-rsa-desc" class="field-hint">
      Maximum legacy compatibility. Slower generation (~5–10 seconds).
    </p>

  </div>
</fieldset>
```

> ⚠️ **Implementation Note:** When `rsa4096` is selected, display an inline advisory:
> `"RSA 4096-bit key generation may take several seconds. The interface will remain responsive."`
> This sets user expectations before they click Generate.

---

### 4.5 Local Passphrase Input (Private Key Protection)

This passphrase is used **only** to encrypt the generated private key before storage. It is **never** transmitted. It is **never** stored in plaintext.

```html
<fieldset class="form-group form-group--passphrase" aria-label="Private Key Protection">
  <legend class="form-group__legend">
    Private Key Passphrase
    <span class="form-group__required-badge" aria-label="required">Required</span>
  </legend>

  <div class="field-wrapper">
    <label for="pgp-passphrase" class="field-label">
      Passphrase
    </label>
    <div class="field-input-wrapper">
      <input
        type="password"
        id="pgp-passphrase"
        name="pgp-passphrase"
        class="field-input"
        autocomplete="new-password"
        autocorrect="off"
        autocapitalize="none"
        spellcheck="false"
        minlength="12"
        aria-required="true"
        aria-describedby="pgp-passphrase-hint pgp-passphrase-strength"
        aria-invalid="false"
      />
      <!-- Show/Hide toggle button -->
      <button
        type="button"
        class="field-reveal-btn"
        aria-label="Show passphrase"
        aria-pressed="false"
        data-target="pgp-passphrase"
      >
        <!-- Eye icon SVG here -->
      </button>
    </div>
    <p id="pgp-passphrase-hint" class="field-hint">
      Protects your private key locally. Use a strong, unique passphrase.
      <strong>There is no recovery mechanism.</strong>
    </p>
    <!-- Strength indicator — injected dynamically -->
    <div id="pgp-passphrase-strength" class="strength-meter" aria-live="polite" aria-atomic="true">
      <!-- Populated by strength estimation logic on input event -->
    </div>
  </div>

  <!-- Passphrase confirmation -->
  <div class="field-wrapper">
    <label for="pgp-passphrase-confirm" class="field-label">
      Confirm Passphrase
    </label>
    <input
      type="password"
      id="pgp-passphrase-confirm"
      name="pgp-passphrase-confirm"
      class="field-input"
      autocomplete="new-password"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      aria-required="true"
      aria-describedby="pgp-passphrase-confirm-error"
      aria-invalid="false"
    />
    <p id="pgp-passphrase-confirm-error" class="field-error" role="alert" hidden></p>
  </div>
</fieldset>
```

---

### 4.6 Publish Toggle (Keyserver Integration Opt-In)

```html
<div class="form-group form-group--publish">

  <!-- Safety Disclosure Banner — always visible when toggle is ON -->
  <div
    id="publish-warning-banner"
    class="warning-banner warning-banner--destructive"
    role="region"
    aria-label="Keyserver Publication Warning"
    hidden
  >
    <!-- Content defined in Layer 5 — Safety Advisory section -->
  </div>

  <label class="checkbox-label" for="pgp-publish">
    <input
      type="checkbox"
      id="pgp-publish"
      name="pgp-publish"
      class="checkbox-input"
      aria-describedby="pgp-publish-hint publish-warning-banner"
    />
    <span class="checkbox-control" aria-hidden="true"></span>
    <span class="checkbox-text">
      Publish Public Key to Global Directory
      <span class="checkbox-subtext">(keys.openpgp.org)</span>
    </span>
  </label>

  <p id="pgp-publish-hint" class="field-hint">
    Makes your public key discoverable by anyone on the internet.
    Read the warning above before enabling.
  </p>

</div>
```

**Toggle Behavior (JavaScript):**

```javascript
document.getElementById('pgp-publish').addEventListener('change', (e) => {
  const banner = document.getElementById('publish-warning-banner');
  banner.hidden = !e.target.checked;

  // If email field is empty and publish is ON, flag it as required
  const emailInput = document.getElementById('pgp-email');
  if (e.target.checked && emailInput.value.trim() === '') {
    emailInput.setAttribute('aria-required', 'true');
    emailInput.setAttribute('aria-invalid', 'false');
    document.getElementById('pgp-email-hint').textContent =
      'An email address is required to publish your key to a keyserver.';
  } else {
    emailInput.setAttribute('aria-required', 'false');
    document.getElementById('pgp-email-hint').textContent =
      'Required only if publishing to a keyserver.';
  }
});
```

---

### 4.7 Generate Button & Loading State

```html
<div class="form-group form-group--actions">
  <button
    type="button"
    id="pgp-generate-btn"
    class="btn btn--primary btn--full-width"
    aria-busy="false"
    aria-live="polite"
  >
    <span class="btn__label">Generate Key Pair</span>
    <span class="btn__spinner" aria-hidden="true" hidden>
      <!-- Spinner SVG or CSS animation -->
    </span>
  </button>
</div>
```

**State Machine for the Generate Button:**

| State | `aria-busy` | Label Text | Spinner | Disabled |
|-------|-------------|------------|---------|----------|
| `idle` | `"false"` | "Generate Key Pair" | hidden | false |
| `generating` | `"true"` | "Generating…" | visible | true |
| `uploading` | `"true"` | "Publishing to Keyserver…" | visible | true |
| `success` | `"false"` | "Key Pair Generated ✓" | hidden | false |
| `error` | `"false"` | "Generation Failed — Retry" | hidden | false |

---

### 4.8 Output Display Component

After successful generation, display a read-only output panel:

```html
<section
  id="pgp-output-panel"
  class="output-panel output-panel--pgp"
  hidden
  aria-label="Generated Key Pair"
>
  <!-- Fingerprint -->
  <div class="output-row">
    <span class="output-label">Fingerprint</span>
    <code id="pgp-fingerprint" class="output-value output-value--mono"></code>
    <button class="btn btn--icon copy-btn" data-copy-target="pgp-fingerprint" aria-label="Copy fingerprint">
      <!-- Copy icon -->
    </button>
  </div>

  <!-- Public Key Block -->
  <div class="output-row output-row--block">
    <span class="output-label">Public Key</span>
    <textarea
      id="pgp-public-key"
      class="output-textarea"
      readonly
      rows="6"
      aria-label="ASCII-armored public key"
      wrap="off"
    ></textarea>
    <button class="btn btn--icon copy-btn" data-copy-target="pgp-public-key" aria-label="Copy public key">
      <!-- Copy icon -->
    </button>
  </div>

  <!-- Private Key (vault-only notice) -->
  <div class="output-row output-row--private">
    <span class="output-label">Private Key</span>
    <div class="output-vault-notice" role="status">
      <svg aria-hidden="true"><!-- lock icon --></svg>
      Encrypted and stored in your local vault.
      <strong>Never leaves your device.</strong>
    </div>
  </div>

  <!-- Keyserver Status (conditionally rendered) -->
  <div id="pgp-keyserver-status" class="output-row" hidden>
    <span class="output-label">Keyserver</span>
    <p id="pgp-keyserver-status-text" role="status" aria-live="polite"></p>
  </div>
</section>
```

---

## 5. Layer 2 — Client-Side Cryptographic Web Worker

### 5.1 Worker File: `pgp.worker.js`

**Location:** `src/workers/pgp.worker.js` (adjust to match your project's `src` structure)

**Why a Web Worker?**
- RSA 4096 key generation can take 3–10 seconds of CPU-bound computation.
- Running this on the main thread freezes all UI interaction, scroll, and animation.
- A Web Worker runs on a separate OS thread, keeping the UI at 60fps.
- The worker has no access to the DOM — this is a security benefit, not just a design constraint.

**Full Worker Implementation Blueprint:**

```javascript
/**
 * @file pgp.worker.js
 * @description Web Worker for PGP key pair generation using openpgp.js.
 *              Runs off the main UI thread to prevent blocking.
 *
 * Communication protocol:
 *   INBOUND  (main → worker): { type: 'GENERATE', payload: GenerateRequest }
 *   OUTBOUND (worker → main): { type: 'SUCCESS',  payload: GenerateResult  }
 *                             { type: 'ERROR',    payload: ErrorResult     }
 *
 * @typedef {Object} GenerateRequest
 * @property {'ecc' | 'rsa4096'} algorithm - Key algorithm selection.
 * @property {string}  [name]              - Optional User ID display name.
 * @property {string}  [email]             - Optional User ID email address.
 * @property {string}  passphrase          - Passphrase to protect the private key.
 *
 * @typedef {Object} GenerateResult
 * @property {string} publicKeyArmored       - ASCII-armored public key block.
 * @property {string} privateKeyArmored      - ASCII-armored encrypted private key block.
 * @property {string} revocationCertificate  - ASCII-armored revocation certificate.
 * @property {string} fingerprint            - Uppercase hex fingerprint of the primary key.
 * @property {string} keyId                  - Short (16-char) key ID.
 * @property {number} createdAt              - Unix timestamp (ms) of key creation.
 *
 * @typedef {Object} ErrorResult
 * @property {string} code    - Machine-readable error code.
 * @property {string} message - Human-readable error description.
 */

import * as openpgp from 'openpgp';

// ─── Message Handler ──────────────────────────────────────────────────────────

self.addEventListener('message', async (event) => {
  const { type, payload } = event.data;

  if (type !== 'GENERATE') {
    self.postMessage({
      type: 'ERROR',
      payload: {
        code: 'UNKNOWN_MESSAGE_TYPE',
        message: `Worker received unknown message type: "${type}".`
      }
    });
    return;
  }

  try {
    const result = await generateKeyPair(payload);
    self.postMessage({ type: 'SUCCESS', payload: result });
  } catch (err) {
    self.postMessage({
      type: 'ERROR',
      payload: {
        code: classifyError(err),
        message: err.message || 'An unknown error occurred during key generation.'
      }
    });
  }
});

// ─── Core Key Generation ──────────────────────────────────────────────────────

/**
 * Generates a PGP key pair based on the provided configuration.
 * @param {GenerateRequest} request
 * @returns {Promise<GenerateResult>}
 */
async function generateKeyPair(request) {
  const { algorithm, name, email, passphrase } = request;

  // Validate required fields inside the worker as a safety net
  if (!passphrase || passphrase.length < 1) {
    throw new Error('A passphrase is required to protect the private key.');
  }

  // Build User ID object — openpgp.js accepts an empty object for anonymous keys
  const userIDs = buildUserIDs(name, email);

  // Construct algorithm-specific openpgp config
  const keyConfig = buildKeyConfig(algorithm, userIDs, passphrase);

  // ── The heavy lifting ──
  const {
    privateKey: privateKeyArmored,
    publicKey: publicKeyArmored,
    revocationCertificate
  } = await openpgp.generateKey(keyConfig);

  // Parse the generated public key to extract metadata
  const parsedPublicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const fingerprint = parsedPublicKey.getFingerprint().toUpperCase();
  const keyId = parsedPublicKey.getKeyID().toHex().toUpperCase();
  const createdAt = parsedPublicKey.getCreationTime().getTime();

  return {
    publicKeyArmored,
    privateKeyArmored,
    revocationCertificate,
    fingerprint,
    keyId,
    createdAt
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Constructs the userIDs array for openpgp.generateKey().
 * Returns an empty array if no identity is provided (anonymous key).
 * @param {string|undefined} name
 * @param {string|undefined} email
 * @returns {Array<{ name?: string, email?: string }>}
 */
function buildUserIDs(name, email) {
  const hasName = name && name.trim().length > 0;
  const hasEmail = email && email.trim().length > 0;

  if (!hasName && !hasEmail) {
    return [{}]; // Anonymous key — valid per OpenPGP spec
  }

  const uid = {};
  if (hasName)  uid.name  = name.trim();
  if (hasEmail) uid.email = email.trim();
  return [uid];
}

/**
 * Builds the openpgp.generateKey() configuration object.
 * @param {'ecc' | 'rsa4096'} algorithm
 * @param {Array}  userIDs
 * @param {string} passphrase
 * @returns {Object} openpgp generateKey config
 */
function buildKeyConfig(algorithm, userIDs, passphrase) {
  const baseConfig = {
    userIDs,
    passphrase,
    format: 'armored'
  };

  if (algorithm === 'rsa4096') {
    return {
      ...baseConfig,
      type: 'rsa',
      rsaBits: 4096
    };
  }

  // Default: ECC Curve25519
  return {
    ...baseConfig,
    type: 'ecc',
    curve: 'curve25519'
  };
}

/**
 * Maps thrown errors to machine-readable codes for structured error handling.
 * @param {Error} err
 * @returns {string}
 */
function classifyError(err) {
  const msg = (err.message || '').toLowerCase();
  if (msg.includes('passphrase')) return 'INVALID_PASSPHRASE';
  if (msg.includes('curve'))      return 'UNSUPPORTED_CURVE';
  if (msg.includes('rsa'))        return 'RSA_GENERATION_FAILED';
  if (msg.includes('userid'))     return 'INVALID_USER_ID';
  return 'KEY_GENERATION_FAILED';
}
```

---

### 5.2 Main Thread — Worker Controller

**Location:** `src/services/pgpWorkerController.js`

```javascript
/**
 * @file pgpWorkerController.js
 * @description Main-thread controller for the pgp.worker.js Web Worker.
 *              Manages worker lifecycle, message passing, and timeout handling.
 */

/** @type {Worker|null} */
let workerInstance = null;

/** Maximum time (ms) to wait for key generation before timing out. */
const WORKER_TIMEOUT_MS = 60_000; // 60 seconds covers RSA 4096 on slow hardware

/**
 * Spawns the PGP worker (lazily), sends a GENERATE request, and returns
 * a Promise that resolves with GenerateResult or rejects with an error.
 *
 * @param {import('./pgp.worker.js').GenerateRequest} request
 * @returns {Promise<import('./pgp.worker.js').GenerateResult>}
 */
export function generatePGPKeyPair(request) {
  return new Promise((resolve, reject) => {
    // Lazy initialization — reuse if already running
    if (!workerInstance) {
      workerInstance = new Worker(
        new URL('../workers/pgp.worker.js', import.meta.url),
        { type: 'module' }
      );
    }

    // Timeout guard
    const timeoutId = setTimeout(() => {
      terminateWorker();
      reject(new Error('Key generation timed out after 60 seconds. Please try again.'));
    }, WORKER_TIMEOUT_MS);

    // One-shot message handlers
    workerInstance.onmessage = (event) => {
      clearTimeout(timeoutId);
      const { type, payload } = event.data;

      if (type === 'SUCCESS') {
        resolve(payload);
      } else if (type === 'ERROR') {
        reject(Object.assign(new Error(payload.message), { code: payload.code }));
      }

      // Clean up handlers after single use
      workerInstance.onmessage = null;
      workerInstance.onerror = null;
    };

    workerInstance.onerror = (errorEvent) => {
      clearTimeout(timeoutId);
      terminateWorker();
      reject(new Error(`Worker crashed: ${errorEvent.message}`));
    };

    // Dispatch the generation request
    workerInstance.postMessage({ type: 'GENERATE', payload: request });
  });
}

/**
 * Terminates the worker and clears the singleton reference.
 * Call this on app teardown or after unrecoverable worker errors.
 */
export function terminateWorker() {
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
  }
}
```

---

## 6. Layer 3 — Vault Interoperability & IndexedDB Storage Schema

### 6.1 New IndexedDB Object Store: `pgpKeys`

The existing vault infrastructure manages an IndexedDB database. Phase 3 adds a **new object store** named `pgpKeys`. The database version must be incremented to trigger the `onupgradeneeded` callback where this store is created.

**Store Creation (in `onupgradeneeded`):**

```javascript
// ── Add inside your existing onupgradeneeded handler ──────────────────────────
// Increment DB version to trigger this migration.

if (!db.objectStoreNames.contains('pgpKeys')) {
  const pgpStore = db.createObjectStore('pgpKeys', {
    keyPath: 'id',          // UUID v4 — generated client-side
    autoIncrement: false
  });

  // Allow O(1) lookup by cryptographic fingerprint
  pgpStore.createIndex('fingerprint', 'fingerprint', { unique: true });

  // Allow reverse-chronological listing
  pgpStore.createIndex('createdAt', 'createdAt', { unique: false });

  // Allow filtering by publication status
  pgpStore.createIndex('published', 'published', { unique: false });
}
```

---

### 6.2 PGP Key Record — Full JSON Schema

```jsonc
{
  // ── Primary Key ────────────────────────────────────────────────────────────
  "id": "550e8400-e29b-41d4-a716-446655440000",
  // Type: string (UUID v4)
  // Generated by: crypto.randomUUID() on the client
  // Purpose: Stable, opaque record identifier within IndexedDB

  // ── Cryptographic Identity ─────────────────────────────────────────────────
  "fingerprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
  // Type: string (40-character uppercase hex)
  // Source: parsedPublicKey.getFingerprint().toUpperCase()
  // Purpose: Global PGP fingerprint; unique per key pair

  "keyId": "66778899AABBCCDD",
  // Type: string (16-character uppercase hex)
  // Source: parsedPublicKey.getKeyID().toHex().toUpperCase()
  // Purpose: Short-form key ID for display; not guaranteed unique across universe

  // ── Key Material ───────────────────────────────────────────────────────────
  "publicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
  // Type: string
  // Sensitivity: PUBLIC — safe to display and transmit
  // Source: openpgp.generateKey() output, .publicKey field

  "encryptedPrivateKey": {
    // Type: object
    // Sensitivity: CONFIDENTIAL — never transmit, never log
    // Description: The ASCII-armored private key is first encrypted by openpgp.js
    //              using the user's passphrase (via S2K/AES-256 internally),
    //              then the resulting armored string is ADDITIONALLY encrypted
    //              by the vault's AES-256-GCM pipeline before storage.
    //
    // Two-layer protection rationale:
    //   Layer 1 (openpgp.js): Passphrase-based S2K encryption — protects the
    //                          private key even if the vault is compromised.
    //   Layer 2 (vault AES-256-GCM): Vault master key encryption — integrates
    //                                 the private key into the existing vault
    //                                 security model.

    "ciphertext": "<base64-encoded AES-256-GCM ciphertext>",
    // Type: string (Base64)
    // Content: AES-256-GCM encrypted version of the ASCII-armored private key
    //          (which is itself passphrase-encrypted by openpgp.js)

    "iv": "<base64-encoded 12-byte nonce>",
    // Type: string (Base64)
    // Content: Randomly generated 96-bit IV for AES-256-GCM
    // MUST be unique per encryption operation — use crypto.getRandomValues()

    "authTag": "<base64-encoded 16-byte auth tag>",
    // Type: string (Base64)
    // Content: AES-256-GCM authentication tag
    // Verifies ciphertext integrity; reject decryption if tag fails

    "kdfSalt": "<base64-encoded 16-byte salt>",
    // Type: string (Base64)
    // Content: PBKDF2/Argon2 salt used to derive the AES key from vault master key
    // NOTE: Use the project's existing KDF approach — do not introduce a new one

    "kdfAlgorithm": "PBKDF2-SHA-256",
    // Type: string
    // Matches the project's existing derivation algorithm identifier
    // Update to "argon2id" if the project uses Argon2

    "encryptionAlgorithm": "AES-256-GCM"
    // Type: string — static identifier for schema version compatibility
  },

  "revocationCertificateEncrypted": {
    // Type: object — same schema as encryptedPrivateKey above
    // Sensitivity: CONFIDENTIAL
    // Description: Encrypted revocation certificate. If the user ever loses
    //              their private key passphrase, they CANNOT revoke without this.
    //              Store it encrypted with the vault key only (not passphrase),
    //              so the user can revoke even if they forget the PGP passphrase.
    "ciphertext": "<base64>",
    "iv": "<base64>",
    "authTag": "<base64>",
    "kdfSalt": "<base64>",
    "kdfAlgorithm": "PBKDF2-SHA-256",
    "encryptionAlgorithm": "AES-256-GCM"
  },

  // ── User Identity (Optional) ───────────────────────────────────────────────
  "identity": {
    "name": "Jane Doe",
    // Type: string | null
    // Sensitivity: LOW — this data is embedded in the public key

    "email": "jane@example.com"
    // Type: string | null
    // Sensitivity: LOW — this data is embedded in the public key
    //              and published to the keyserver if opted in
  },

  // ── Algorithm Metadata ─────────────────────────────────────────────────────
  "algorithm": {
    "type": "ecc",
    // Type: string — "ecc" | "rsa"

    "curve": "curve25519",
    // Type: string | null — present only when type === "ecc"

    "rsaBits": null
    // Type: number | null — present only when type === "rsa" (value: 4096)
  },

  // ── Timestamps ─────────────────────────────────────────────────────────────
  "createdAt": 1749600000000,
  // Type: number (Unix epoch, milliseconds)
  // Source: parsedPublicKey.getCreationTime().getTime()
  // Note: This is the cryptographic key creation time, not the vault save time

  "savedAt": 1749600001234,
  // Type: number (Unix epoch, milliseconds)
  // Source: Date.now() at the moment of IndexedDB write
  // Note: savedAt >= createdAt always; difference indicates processing time

  // ── Keyserver Publication Status ───────────────────────────────────────────
  "published": false,
  // Type: boolean
  // Initial value: false
  // Set to: true after successful POST to keys.openpgp.org

  "publishedAt": null,
  // Type: number | null (Unix epoch, milliseconds)
  // Set to: Date.now() value at time of successful keyserver response

  "keyserverToken": null,
  // Type: string | null
  // Source: token field from /vks/v1/upload JSON response
  // Purpose: Used for subsequent /vks/v1/request-verify calls
  // Security: This token is not a secret, but store it for future UX use

  "emailVerificationPending": false
  // Type: boolean
  // Set to: true after requesting email verification via /vks/v1/request-verify
  // Set to: false after user manually re-checks (no webhook available in browser)
}
```

---

### 6.3 Vault Encryption Helper — Private Key Storage Pipeline

```javascript
/**
 * @file vaultPGPStorage.js
 * @description Handles the two-layer encryption and storage of PGP private key material.
 *
 * Encryption Pipeline:
 *
 *   plaintext armored private key (from openpgp.js, already passphrase-encrypted)
 *       │
 *       ▼
 *   [AES-256-GCM encrypt using vault master key derived via existing KDF]
 *       │
 *       ▼
 *   { ciphertext, iv, authTag, kdfSalt } object stored in IndexedDB
 */

/**
 * Encrypts the ASCII-armored private key string using the vault's AES-256-GCM
 * pipeline and returns the encrypted payload object.
 *
 * IMPORTANT: This function must use the project's existing KDF and AES-GCM
 * implementation. Do NOT introduce new cryptographic primitives.
 *
 * @param {string} armoredPrivateKey     - ASCII-armored, passphrase-protected private key.
 * @param {CryptoKey} vaultMasterKey     - The vault's active AES-256-GCM CryptoKey.
 * @returns {Promise<EncryptedKeyBlock>}
 */
export async function encryptPrivateKeyForVault(armoredPrivateKey, vaultMasterKey) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(armoredPrivateKey);

  // Generate a cryptographically random 96-bit IV (12 bytes) per NIST SP 800-38D
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    vaultMasterKey,
    plaintext
  );

  // AES-GCM appends 16-byte auth tag to ciphertext — split them
  const fullOutput  = new Uint8Array(ciphertextBuffer);
  const ciphertext  = fullOutput.slice(0, fullOutput.length - 16);
  const authTag     = fullOutput.slice(fullOutput.length - 16);

  return {
    ciphertext: bufferToBase64(ciphertext),
    iv:         bufferToBase64(iv),
    authTag:    bufferToBase64(authTag),
    kdfSalt:    null, // Populate with your project's KDF salt if applicable
    kdfAlgorithm:       'PBKDF2-SHA-256',
    encryptionAlgorithm: 'AES-256-GCM'
  };
}

/**
 * Decrypts an encrypted key block and returns the ASCII-armored private key string.
 *
 * @param {EncryptedKeyBlock} encryptedBlock
 * @param {CryptoKey} vaultMasterKey
 * @returns {Promise<string>} ASCII-armored private key
 */
export async function decryptPrivateKeyFromVault(encryptedBlock, vaultMasterKey) {
  const iv         = base64ToBuffer(encryptedBlock.iv);
  const ciphertext = base64ToBuffer(encryptedBlock.ciphertext);
  const authTag    = base64ToBuffer(encryptedBlock.authTag);

  // Re-assemble ciphertext + auth tag as a single buffer (WebCrypto convention)
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.length);

  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    vaultMasterKey,
    combined
  );

  return new TextDecoder().decode(plaintextBuffer);
}

// ── Utility ───────────────────────────────────────────────────────────────────

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
```

---

## 7. Layer 4 — Serverless Keyserver Integration (HKP/VKS)

### 7.1 API Endpoint Reference

| Property | Value |
|----------|-------|
| **Base URL** | `https://keys.openpgp.org` |
| **Upload Endpoint** | `POST /vks/v1/upload` |
| **Content-Type** | `application/json` |
| **Payload Field** | `keytext` (string: ASCII-armored public key) |
| **Auth Required** | None for upload; email verification is out-of-band |
| **Rate Limiting** | Server-enforced; implement exponential backoff |
| **CORS** | Public endpoint; no credentials needed |

> ⚠️ **Endpoint Clarification:** The correct upload path is `/vks/v1/upload`, not `/vks/v1/add`.
> The `/add` path is the legacy HKP endpoint and does not return structured JSON responses.
> Always use `/vks/v1/upload` for the JSON API.

---

### 7.2 Upload Response Schema

```jsonc
// Successful upload response from POST /vks/v1/upload
{
  "token": "opaque-string-for-verify-requests",
  // Use this in subsequent /vks/v1/request-verify calls

  "key_fpr": "AABBCCDDEEFF00112233445566778899AABBCCDD",
  // Fingerprint of the uploaded key — verify this matches your local fingerprint

  "status": {
    "jane@example.com": "unpublished"
    // Possible values:
    //   "unpublished" — key uploaded but email not yet verified
    //   "published"   — email verified, key is publicly discoverable
    //   "revoked"     — key has been revoked
    //   "pending"     — verification email sent, awaiting click
  }
}
```

---

### 7.3 Keyserver Service — Full Implementation Blueprint

**Location:** `src/services/keyserverService.js`

```javascript
/**
 * @file keyserverService.js
 * @description Handles all interactions with the keys.openpgp.org VKS API.
 *
 * Public API:
 *   uploadPublicKey(armoredPublicKey)  → Promise<UploadResult>
 *   requestEmailVerification(token, emailAddresses) → Promise<VerifyResult>
 *
 * @typedef {Object} UploadResult
 * @property {boolean} success
 * @property {string}  token        - Opaque token for subsequent verify requests.
 * @property {string}  fingerprint  - Server-confirmed key fingerprint.
 * @property {Object}  status       - Map of email → publication status.
 * @property {string}  [error]      - Error message if success === false.
 * @property {string}  [errorCode]  - Machine-readable error code.
 */

const VKS_BASE_URL   = 'https://keys.openpgp.org';
const UPLOAD_PATH    = '/vks/v1/upload';
const VERIFY_PATH    = '/vks/v1/request-verify';

/** Maximum number of retry attempts on transient failures. */
const MAX_RETRIES    = 3;

/** Base delay for exponential backoff (ms). */
const BACKOFF_BASE   = 1000;

// ─── Upload ───────────────────────────────────────────────────────────────────

/**
 * Uploads an ASCII-armored public key to keys.openpgp.org.
 * Implements retry with exponential backoff for transient network failures.
 *
 * PRECONDITIONS (caller must ensure before calling):
 *   1. User has checked the publish toggle.
 *   2. User has confirmed the safety disclosure modal.
 *   3. The key contains at least one User ID with a valid email address.
 *
 * @param {string} armoredPublicKey - ASCII-armored OpenPGP public key block.
 * @returns {Promise<UploadResult>}
 */
export async function uploadPublicKey(armoredPublicKey) {
  let lastError;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      // Exponential backoff: 1s, 2s, 4s
      await sleep(BACKOFF_BASE * Math.pow(2, attempt - 1));
    }

    try {
      const result = await attemptUpload(armoredPublicKey);
      return result;
    } catch (err) {
      lastError = err;

      // Do NOT retry client errors (4xx) — they won't resolve by retrying
      if (err.statusCode >= 400 && err.statusCode < 500) {
        break;
      }
      // Retry server errors (5xx) and network errors
    }
  }

  return {
    success:   false,
    error:     lastError.message || 'Upload failed after maximum retries.',
    errorCode: lastError.code    || 'UPLOAD_FAILED'
  };
}

/**
 * Performs a single upload attempt.
 * @param {string} armoredPublicKey
 * @returns {Promise<UploadResult>}
 * @throws {Object} { message, code, statusCode } on failure
 */
async function attemptUpload(armoredPublicKey) {
  let response;

  try {
    response = await fetch(`${VKS_BASE_URL}${UPLOAD_PATH}`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept':        'application/json'
      },
      body: JSON.stringify({ keytext: armoredPublicKey }),
      // No credentials — this is a public API
      credentials: 'omit',
      // Respect browser timeout defaults; add AbortController if needed
      signal: AbortSignal.timeout(30_000)  // 30-second hard timeout
    });
  } catch (networkErr) {
    // fetch() itself throws on network failure (no response at all)
    const err = new Error(
      'Could not reach keys.openpgp.org. Check your internet connection.'
    );
    err.code = 'NETWORK_ERROR';
    throw err;
  }

  // ── Parse response ────────────────────────────────────────────────────────

  let body;
  try {
    body = await response.json();
  } catch {
    const err = new Error('Server returned an unreadable response.');
    err.code       = 'PARSE_ERROR';
    err.statusCode = response.status;
    throw err;
  }

  // ── Handle HTTP errors ────────────────────────────────────────────────────

  if (!response.ok) {
    const err = new Error(
      interpretHttpError(response.status, body)
    );
    err.code       = `HTTP_${response.status}`;
    err.statusCode = response.status;
    throw err;
  }

  // ── Validate response structure ───────────────────────────────────────────

  if (!body.token || !body.key_fpr || !body.status) {
    const err = new Error('Server response is missing required fields.');
    err.code       = 'INVALID_RESPONSE';
    err.statusCode = response.status;
    throw err;
  }

  return {
    success:     true,
    token:       body.token,
    fingerprint: body.key_fpr,
    status:      body.status
  };
}

// ─── Request Email Verification ───────────────────────────────────────────────

/**
 * Requests that keys.openpgp.org send a verification email for the specified
 * addresses. Must be called after a successful uploadPublicKey().
 *
 * @param {string}   token          - Opaque token from the upload response.
 * @param {string[]} emailAddresses - List of email addresses to verify.
 * @param {string[]} [locale]       - Preferred locales for the email (optional).
 * @returns {Promise<UploadResult>}
 */
export async function requestEmailVerification(token, emailAddresses, locale = ['en']) {
  try {
    const response = await fetch(`${VKS_BASE_URL}${VERIFY_PATH}`, {
      method:      'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept':        'application/json'
      },
      body: JSON.stringify({
        token,
        addresses: emailAddresses,
        locale
      }),
      credentials: 'omit',
      signal:      AbortSignal.timeout(30_000)
    });

    const body = await response.json();

    if (!response.ok) {
      return {
        success:   false,
        error:     interpretHttpError(response.status, body),
        errorCode: `HTTP_${response.status}`
      };
    }

    return {
      success:     true,
      token:       body.token,
      fingerprint: body.key_fpr,
      status:      body.status
    };
  } catch (err) {
    return {
      success:   false,
      error:     err.message || 'Failed to request email verification.',
      errorCode: err.code    || 'VERIFY_REQUEST_FAILED'
    };
  }
}

// ─── Error Interpretation ─────────────────────────────────────────────────────

/**
 * Translates HTTP status codes from keys.openpgp.org into user-friendly messages.
 * @param {number} status
 * @param {Object} body - Parsed response body (may contain .error field)
 * @returns {string}
 */
function interpretHttpError(status, body) {
  const serverMessage = body?.error || body?.message || '';

  switch (status) {
    case 400:
      return `The key could not be parsed by the keyserver. ${serverMessage}`.trim();
    case 413:
      return 'The key is too large to be accepted by the keyserver.';
    case 415:
      return 'The keyserver rejected the request format. This is a bug — please report it.';
    case 422:
      return `The key was rejected: ${serverMessage || 'unprocessable key data.'}`;
    case 429:
      return 'Too many requests to the keyserver. Please wait a few minutes and try again.';
    case 500:
    case 502:
    case 503:
    case 504:
      return 'The keyserver is temporarily unavailable. Please try again later.';
    default:
      return `Unexpected keyserver response (HTTP ${status}). ${serverMessage}`.trim();
  }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
```

---

### 7.4 Post-Upload UX Flow

```
User clicks "Generate Key Pair"
         │
         ▼
[Validation: passphrase confirmed, email valid if publish=ON]
         │
         ▼
[Worker: generate key pair] ──── (3–10 seconds) ────
         │
         ▼
[Vault: encrypt & store private key + revocation cert]
         │
         ▼
   publish toggle ON?
      │           │
     YES          NO → Show output panel, done.
      │
      ▼
[Show confirmation modal with safety disclosure]
      │
   User confirms
      │
      ▼
[keyserverService.uploadPublicKey(armoredPublicKey)]
      │
  ┌───┴────────────────────────────┐
 OK                              ERROR
  │                                │
  ▼                                ▼
[Show success notice:]        [Show error notice with retry button]
"Your public key was          "Upload failed: [error message]"
 uploaded. Check your         "Your key was saved locally. You can
 email to complete            retry publishing from the Keys vault."
 verification."
  │
  ▼
[keyserverService.requestEmailVerification(token, [email])]
  │
  ▼
[Show verification pending notice:]
"A verification email was sent to jane@example.com by keys.openpgp.org.
 Click the link in that email to make your key publicly searchable.
 This is an automated email from keys.openpgp.org, not from Starpass."
```

---

## 8. Layer 5 — User Safety Advisory & Disclosure Framework

### 8.1 Inline Warning Banner (Always Visible When Publish Toggle Is ON)

```html
<div
  id="publish-warning-banner"
  class="warning-banner warning-banner--destructive"
  role="region"
  aria-label="Important: Public Keyserver Warning"
>
  <div class="warning-banner__icon" aria-hidden="true">
    <!-- Warning triangle SVG -->
    <svg viewBox="0 0 24 24" width="20" height="20">
      <path d="M12 2L1 21h22L12 2zm0 3.5L20.5 19h-17L12 5.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"
            fill="currentColor"/>
    </svg>
  </div>
  <div class="warning-banner__content">
    <strong class="warning-banner__title">
      ⚠ Publishing to a Global, Permanent Public Directory
    </strong>
    <ul class="warning-banner__list">
      <li>
        Your public key and the name/email address you entered will be uploaded
        to <strong>keys.openpgp.org</strong>, a publicly accessible, globally
        distributed keyserver.
      </li>
      <li>
        <strong>This cannot be undone.</strong> While you can revoke a key,
        already-distributed copies may persist indefinitely on other servers
        and in recipients' keyrings.
      </li>
      <li>
        Your email address will be visible to anyone who searches for your
        key by fingerprint. After email verification, it becomes searchable
        by email address as well.
      </li>
      <li>
        Starpass has no relationship with keys.openpgp.org and cannot control
        or delete your key once published.
      </li>
      <li>
        <strong>Only publish if you understand and accept these conditions.</strong>
      </li>
    </ul>
  </div>
</div>
```

---

### 8.2 Pre-Publish Confirmation Modal

This modal must be shown and explicitly confirmed before any network call is made.
It is shown **after** the user clicks "Generate Key Pair" and validation passes, **if** the publish toggle is ON.

```html
<dialog
  id="publish-confirm-modal"
  class="modal modal--warning"
  aria-modal="true"
  aria-labelledby="publish-modal-title"
  aria-describedby="publish-modal-description"
>
  <div class="modal__header">
    <h2 id="publish-modal-title" class="modal__title">
      Confirm Public Key Publication
    </h2>
  </div>

  <div class="modal__body">
    <p id="publish-modal-description">
      You are about to publish your public key to <strong>keys.openpgp.org</strong>,
      a global OpenPGP keyserver. Please read the following carefully:
    </p>

    <dl class="confirm-detail-list">
      <dt>What will be published:</dt>
      <dd>Your OpenPGP public key, including the name and email address you provided.</dd>

      <dt>Who can see it:</dt>
      <dd>Anyone on the internet who searches keys.openpgp.org for your email address or key fingerprint.</dd>

      <dt>Can it be removed:</dt>
      <dd>
        <strong>No.</strong> Public keyservers are append-only. You can upload a
        revocation certificate to mark the key as revoked, but the key data itself
        cannot be deleted from the distributed network.
      </dd>

      <dt>Starpass's role:</dt>
      <dd>
        Starpass sends the upload request on your behalf. Starpass does not operate
        or have any administrative access to keys.openpgp.org.
      </dd>

      <dt>After publishing:</dt>
      <dd>
        You will receive a verification email at <strong id="publish-confirm-email"></strong>
        from <code>noreply@keys.openpgp.org</code>. You must click the link in that
        email for your key to become searchable by email address.
      </dd>
    </dl>

    <!-- Explicit acknowledgement checkbox — required before confirm button activates -->
    <label class="checkbox-label checkbox-label--prominent">
      <input
        type="checkbox"
        id="publish-confirm-ack"
        class="checkbox-input"
        required
        aria-required="true"
      />
      <span class="checkbox-control" aria-hidden="true"></span>
      <span class="checkbox-text">
        I understand that publishing my public key is permanent and globally visible.
        I consent to this publication.
      </span>
    </label>
  </div>

  <div class="modal__footer">
    <button
      type="button"
      id="publish-cancel-btn"
      class="btn btn--secondary"
      autofocus
    >
      Cancel — Do Not Publish
    </button>
    <button
      type="button"
      id="publish-confirm-btn"
      class="btn btn--destructive"
      disabled
      aria-disabled="true"
    >
      Confirm — Publish My Key
    </button>
  </div>
</dialog>
```

**Modal Controller (JavaScript):**

```javascript
/**
 * Activates the "Confirm" button only after the acknowledgement checkbox is checked.
 * Prevents accidental or unconsidered keyserver publication.
 */
document.getElementById('publish-confirm-ack').addEventListener('change', (e) => {
  const confirmBtn = document.getElementById('publish-confirm-btn');
  confirmBtn.disabled       = !e.target.checked;
  confirmBtn.ariaDisabled   = String(!e.target.checked);
});

/**
 * Returns a Promise that resolves to true (user confirmed) or false (user cancelled).
 * Populates the email preview in the modal before showing it.
 *
 * @param {string} email - The email address that will be published.
 * @returns {Promise<boolean>}
 */
function showPublishConfirmModal(email) {
  return new Promise((resolve) => {
    const modal = document.getElementById('publish-confirm-modal');

    // Reset state
    document.getElementById('publish-confirm-ack').checked = false;
    document.getElementById('publish-confirm-btn').disabled = true;
    document.getElementById('publish-confirm-email').textContent = email;

    modal.showModal();

    const onConfirm = () => {
      cleanup();
      resolve(true);
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    // Close on Escape key (native dialog behavior) or cancel button
    const onClose = () => { cleanup(); resolve(false); };

    document.getElementById('publish-confirm-btn').addEventListener('click', onConfirm, { once: true });
    document.getElementById('publish-cancel-btn').addEventListener('click', onCancel,  { once: true });
    modal.addEventListener('close', onClose, { once: true });

    function cleanup() {
      modal.close();
      // Event listeners are removed via { once: true } above
    }
  });
}
```

---

### 8.3 Post-Upload Notification Strings

These strings must be displayed in the output panel's keyserver status row:

```javascript
const KEYSERVER_NOTIFICATIONS = {

  UPLOAD_SUCCESS_PENDING_VERIFICATION: (email) =>
    `Your public key was successfully uploaded to keys.openpgp.org. ` +
    `A verification email has been sent to ${email} by keys.openpgp.org. ` +
    `Click the link in that email to make your key searchable by email address. ` +
    `If you do not verify, your key will be stored on the keyserver but will ` +
    `not be discoverable by email.`,

  UPLOAD_SUCCESS_NO_EMAIL:
    `Your public key was uploaded to keys.openpgp.org. ` +
    `Because no email address was provided, it is only searchable by fingerprint. ` +
    `No verification email will be sent.`,

  UPLOAD_FAILED_NETWORK:
    `Upload failed: Could not reach keys.openpgp.org. ` +
    `Your key pair was saved to your local vault. ` +
    `You can retry publishing from the Keys vault at any time.`,

  UPLOAD_FAILED_SERVER: (message) =>
    `The keyserver rejected the upload: ${message} ` +
    `Your key pair was saved locally. ` +
    `If this problem persists, try generating a new key pair.`,

  REVOCATION_WARNING:
    `Store your revocation certificate safely. ` +
    `It is the only way to invalidate your key on the keyserver ` +
    `if you lose access to your private key.`
};
```

---

## 9. Security Threat Model & Mitigations

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Private key exfiltration via network | Critical | Private key material is NEVER sent over the network. Only the public key is transmitted to the keyserver, and only when explicitly opted in. |
| Private key theft from IndexedDB | High | Two-layer encryption: openpgp.js S2K passphrase encryption + vault AES-256-GCM. Attacker needs both the vault master key AND the PGP passphrase to decrypt. |
| Main thread blocking during key gen | Medium | Mitigated entirely by Web Worker architecture. Worker executes openpgp.js off-thread. |
| XSS extraction of in-memory key material | High | Key material only exists in memory during generation (worker) and brief display window. Clear sensitive variables immediately after vault storage. |
| Accidental keyserver publication | Medium | Two-stage consent: (1) explicit toggle, (2) modal with acknowledgement checkbox. Cannot publish without both. |
| MITM on keyserver upload | Low | HTTPS enforced. `credentials: 'omit'` prevents cookie leakage. No auth tokens transmitted. |
| Worker message injection | Low | Worker only responds to `{ type: 'GENERATE' }` messages. All other types return an error — no opaque execution paths. |
| Fingerprint mismatch (key substitution) | Medium | After upload, server-returned `key_fpr` is compared against locally computed `fingerprint`. Mismatch triggers an error and does NOT mark the key as published. |

---

## 10. Dependency Manifest

| Package | Version Constraint | Purpose | Install |
|---------|-------------------|---------|---------|
| `openpgp` | `^6.0.0` | PGP key generation, parsing, fingerprinting | `npm install openpgp` |

> **Note:** `openpgp.js` v6+ has full ES Module support and works cleanly inside Web Workers with `import * as openpgp from 'openpgp'`. Do NOT use v4 or v5 — their Worker compatibility is limited.

No other new dependencies are required. All other functionality uses:
- Native `crypto.subtle` (Web Crypto API)
- Native `fetch` (Fetch API)
- Native `Worker` (Web Workers API)
- Native `indexedDB` (already used by the vault)
- Native `<dialog>` element (modal)

---

## 11. Testing Strategy

### 11.1 Unit Tests

| Module | Test Cases |
|--------|------------|
| `validateEmail()` | Empty string → valid; valid emails → valid; malformed → invalid |
| `buildUserIDs()` | Both empty → `[{}]`; name only; email only; both present |
| `buildKeyConfig()` | ECC → type=ecc, curve=curve25519; RSA → type=rsa, rsaBits=4096 |
| `classifyError()` | Maps known error strings to correct codes |
| `encryptPrivateKeyForVault()` | Ciphertext is not plaintext; IV is unique per call; decryption round-trips |
| `interpretHttpError()` | Each HTTP code maps to expected string |

### 11.2 Integration Tests

| Scenario | Expected Outcome |
|----------|-----------------|
| Generate ECC key with identity, no publish | Key stored in vault; no network calls |
| Generate RSA key, no identity, no publish | Key stored without UserID; no network calls |
| Generate key with publish=ON, confirmed | Upload called once; token stored; verify requested |
| Generate key with publish=ON, user cancels modal | Upload NOT called; key stored locally only |
| Worker timeout (mock 61s delay) | UI unblocked; error displayed; no partial data stored |
| Network failure during upload | Key saved locally; error notification shown; retry available |
| Server returns mismatched fingerprint | `published` stays false; error logged; warning shown |

### 11.3 Accessibility Tests

- Full keyboard navigation through all form fields (Tab order, Escape to close modal)
- Screen reader announces dynamic field errors (`role="alert"`, `aria-live`)
- Button states (busy, disabled) announced correctly
- Modal focus trap: focus stays within `<dialog>` while open
- Color contrast: warning banner and error text meet WCAG AA (4.5:1 ratio)

---

## 12. Implementation Checklist

Use this checklist to track implementation progress:

### Frontend
- [ ] Add 4th tab button (`Keys`) with ARIA attributes
- [ ] Create `panel-keys` section (hidden by default)
- [ ] Implement `IdentityForm` with Name + Email fields
- [ ] Implement email validation with ARIA error announcements
- [ ] Implement `AlgorithmToggle` (ECC / RSA radio group)
- [ ] Add RSA advisory text when RSA is selected
- [ ] Implement `PassphraseInput` with show/hide toggle
- [ ] Implement passphrase confirmation field with match validation
- [ ] Implement passphrase strength meter
- [ ] Implement `PublishToggle` checkbox
- [ ] Wire publish toggle to show/hide warning banner
- [ ] Wire publish toggle to conditionally require email
- [ ] Implement `GenerateButton` with 5-state machine (idle/generating/uploading/success/error)
- [ ] Implement `OutputPanel` with fingerprint, public key, vault notice, keyserver status

### Web Worker
- [ ] Create `src/workers/pgp.worker.js`
- [ ] Install `openpgp` v6+
- [ ] Implement `generateKeyPair()` with ECC + RSA support
- [ ] Implement `buildUserIDs()` helper
- [ ] Implement `buildKeyConfig()` helper
- [ ] Implement `classifyError()` helper
- [ ] Create `src/services/pgpWorkerController.js`
- [ ] Implement `generatePGPKeyPair()` with timeout guard
- [ ] Implement `terminateWorker()` cleanup

### Vault / Storage
- [ ] Increment IndexedDB version number
- [ ] Create `pgpKeys` object store in `onupgradeneeded`
- [ ] Create `fingerprint` index (unique)
- [ ] Create `createdAt` index
- [ ] Create `published` index
- [ ] Implement `encryptPrivateKeyForVault()`
- [ ] Implement `decryptPrivateKeyFromVault()`
- [ ] Wire full key record assembly + IndexedDB write

### Keyserver Integration
- [ ] Create `src/services/keyserverService.js`
- [ ] Implement `uploadPublicKey()` with retry + backoff
- [ ] Implement `requestEmailVerification()`
- [ ] Implement `interpretHttpError()`
- [ ] Verify fingerprint matches after upload
- [ ] Update `published`, `publishedAt`, `keyserverToken` on success

### Safety & UX
- [ ] Implement inline `publish-warning-banner` (shown when toggle is ON)
- [ ] Implement `publish-confirm-modal` with `<dialog>`
- [ ] Implement acknowledgement checkbox gating the Confirm button
- [ ] Populate email preview in modal before showing
- [ ] Implement `showPublishConfirmModal()` Promise wrapper
- [ ] Display all `KEYSERVER_NOTIFICATIONS` strings in correct scenarios
- [ ] Show revocation certificate warning in output panel

### Testing
- [ ] Unit tests for all utility functions
- [ ] Integration tests for key generation flow
- [ ] Integration tests for keyserver upload flow (mocked)
- [ ] Accessibility audit (keyboard + screen reader)
- [ ] Cross-browser test: Chrome, Firefox, Safari (Web Worker + SubtleCrypto)

---

*End of Blueprint — `pgp-key-server-implementation.md`*

> **Implementation Note for Returning Developer:**
> This document is entirely additive. No existing files are modified by this specification.
> Begin with the IndexedDB migration (bump the version, add the store), then the Worker,
> then the UI layer. The keyserver service can be developed and mocked independently
> of the cryptographic layer. Good luck with your exams — the architecture will be here
> when you're back. 🔑
