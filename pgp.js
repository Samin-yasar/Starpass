/**
 * pgp.js — Starpass Phase 3
 *
 * Main-thread PGP controller. Manages:
 *  - Web Worker lifecycle (lazy init, per-generation timeout, terminate on error)
 *  - Keys tab form validation
 *  - Button state machine (idle → generating → saving → done)
 *  - Vault storage — encrypts private key with the vault master key (AES-256-GCM)
 *    via PasswordHistoryManager.getMasterKey() + crypto.subtle directly.
 *    This avoids duplicating the vault pipeline while keeping private key local-only.
 *  - Keyserver publish flow with confirm modal (reuses existing .modal-overlay pattern)
 *  - Keys vault list (displays stored key records)
 *
 * Dependencies (must load before this script):
 *   history.js  → window.PasswordHistoryManager  (with getMasterKey exposed)
 *   src/services/keyserverService.js → window.KeyserverService
 *   src/zxcvbn.min.js → window.zxcvbn
 */
const PGPManager = (() => {
    // ── Constants ────────────────────────────────────────────────────────────
    const WORKER_PATH      = 'src/workers/pgp.worker.js';
    const WORKER_TIMEOUT   = 30_000;   // 30 s max; ECC key generation is instant
    const PGP_STORE        = 'pgpKeys';
    const EMAIL_REGEX      = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const MIN_PASS_LEN     = 12;

    // ── State ─────────────────────────────────────────────────────────────────
    let _worker        = null;
    let _workerTimer   = null;
    let _generating    = false;
    let _lastResult    = null;    // last successful generation payload

    // ── Utility ───────────────────────────────────────────────────────────────
    function $(id) { return document.getElementById(id); }

    function toast(msg, ok = false) {
        const c = $('toast-container');
        if (!c) return;
        const t = document.createElement('div');
        t.className   = `toast ${ok ? 'success' : 'error'}`;
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => t.remove(), 4000);
    }

    // ── Worker lifecycle ──────────────────────────────────────────────────────

    function terminateWorker() {
        if (_workerTimer) { clearTimeout(_workerTimer); _workerTimer = null; }
        if (_worker)      { _worker.terminate(); _worker = null; }
    }

    /**
     * Lazily creates the Web Worker, sends GENERATE message, returns a Promise
     * that resolves with the SUCCESS payload or rejects with { code, message }.
     */
    function runWorker(payload) {
        return new Promise((resolve, reject) => {
            terminateWorker();

            let worker;
            try {
                worker = new Worker(WORKER_PATH);
            } catch (e) {
                reject({ code: 'WORKER_INIT_FAILED', message: 'Could not start key generation worker. ' + (e.message || '') });
                return;
            }
            _worker = worker;

            // Hard timeout — terminates the worker if key generation stalls
            _workerTimer = setTimeout(() => {
                terminateWorker();
                reject({ code: 'GENERATION_TIMEOUT', message: 'Key generation timed out. Please try again.' });
            }, WORKER_TIMEOUT);

            worker.onmessage = (evt) => {
                const { type, payload: data } = evt.data || {};

                if (type === 'PROGRESS') {
                    setStatus(data && data.message ? data.message : 'Working…');
                    return;
                }

                if (type === 'SUCCESS') {
                    terminateWorker();
                    resolve(data);
                    return;
                }

                if (type === 'ERROR') {
                    terminateWorker();
                    reject(data || { code: 'UNKNOWN_ERROR', message: 'Unknown worker error.' });
                    return;
                }
            };

            worker.onerror = (e) => {
                terminateWorker();
                reject({
                    code:    'WORKER_RUNTIME_ERROR',
                    message: e.message || 'Worker runtime error — check the browser console.'
                });
            };

            worker.postMessage({ type: 'GENERATE', payload });
        });
    }

    // ── Button / UI state machine ─────────────────────────────────────────────

    function setStatus(msg) {
        const el = $('pgp-status');
        if (el) el.textContent = msg;
    }

    function setBusy(busy, label = 'Generating…') {
        const btn = $('pgp-generate-btn');
        if (!btn) return;
        btn.disabled = busy;
        btn.dataset.busy = busy ? 'true' : 'false';
        // Swap spinner / icon
        const textSpan = btn.querySelector('.btn-label');
        if (textSpan) textSpan.textContent = busy ? label : 'Generate Key Pair';
        _generating = busy;
    }

    function showOutput(result) {
        const panel = $('pgp-output-panel');
        if (!panel) return;

        $('pgp-out-fingerprint').textContent  = formatFingerprint(result.fingerprint);
        $('pgp-out-keyid').textContent        = result.keyId || '—';
        $('pgp-out-algorithm').textContent    = result.algorithmLabel || '—';
        $('pgp-out-created').textContent      = result.createdAt
            ? new Date(result.createdAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
            : '—';
        $('pgp-out-pubkey').value             = result.publicKeyArmored || '';

        panel.classList.remove('hidden');
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function hideOutput() {
        const panel = $('pgp-output-panel');
        if (panel) panel.classList.add('hidden');
    }

    function formatFingerprint(fp) {
        if (!fp) return '—';
        // Format as groups of 4: ABCD EFGH …
        return fp.replace(/(.{4})/g, '$1 ').trim();
    }

    // ── Vault: AES-256-GCM encrypt/decrypt (mirrors history.js) ──────────────

    async function vaultEncrypt(plaintext, masterKey) {
        const iv          = crypto.getRandomValues(new Uint8Array(12));
        const encBuf      = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            new TextEncoder().encode(plaintext)
        );
        return { iv, encryptedData: encBuf };
    }

    async function vaultDecrypt(iv, encryptedData, masterKey) {
        const buf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            encryptedData
        );
        return new TextDecoder().decode(buf);
    }

    // ── IndexedDB helpers (pgpKeys store) ────────────────────────────────────

    function getDB() {
        return window.PasswordHistoryManager && window.PasswordHistoryManager._db
            ? window.PasswordHistoryManager._db
            : null;
    }

    /**
     * Opens the DB directly — we need the pgpKeys store added in DB_VERSION 4.
     * PasswordHistoryManager.init() already opened and upgraded the DB, so we
     * re-open at the same name/version to get the same instance.
     */
    function openPGPDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open('StarpassDB', 4);
            req.onsuccess = e => resolve(e.target.result);
            req.onerror   = e => reject(e.target.error);
            // onupgradeneeded is handled by history.js; we just re-connect
            req.onupgradeneeded = e => {
                // This shouldn't trigger here (history.js already upgraded),
                // but if it does, create the pgpKeys store safely.
                const d = e.target.result;
                if (!d.objectStoreNames.contains('pgpKeys')) {
                    const st = d.createObjectStore('pgpKeys', { keyPath: 'id', autoIncrement: true });
                    st.createIndex('fingerprint', 'fingerprint', { unique: true });
                    st.createIndex('createdAt',   'createdAt',   { unique: false });
                    st.createIndex('published',   'published',   { unique: false });
                }
            };
        });
    }

    let _pgpDB = null;
    async function getPGPDB() {
        if (!_pgpDB) _pgpDB = await openPGPDB();
        return _pgpDB;
    }

    function idbReq(req) {
        return new Promise((res, rej) => {
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
    }
    function idbTx(tx) {
        return new Promise((res, rej) => {
            tx.oncomplete = res;
            tx.onerror    = e => rej(e.target.error);
        });
    }

    async function saveKeyToVault(result, masterKey) {
        const db = await getPGPDB();

        // Double-encrypt private key:
        //   Layer 1 (openpgp internal): the armored private key is already S2K/AES-256 encrypted by openpgp
        //   Layer 2 (vault): additionally wrap with vault master key AES-256-GCM
        const { iv, encryptedData } = await vaultEncrypt(result.privateKeyArmored, masterKey);

        // Encrypt the revocation certificate too (sensitive)
        const revoc = await vaultEncrypt(result.revocationCertificate || '', masterKey);

        const record = {
            fingerprint:           result.fingerprint,
            keyId:                 result.keyId,
            algorithmLabel:        result.algorithmLabel,
            createdAt:             result.createdAt,
            // Public key stored in cleartext — it's public
            publicKeyArmored:      result.publicKeyArmored,
            // Private key double-encrypted
            encryptedPrivateKey:   { iv, encryptedData },
            // Revocation cert encrypted
            encryptedRevocation:   { iv: revoc.iv, encryptedData: revoc.encryptedData },
            published:             false,
            publishedAt:           null,
            savedAt:               new Date().toISOString()
        };

        const tx = db.transaction([PGP_STORE], 'readwrite');
        const id = await idbReq(tx.objectStore(PGP_STORE).add(record));
        await idbTx(tx);
        return id;
    }

    async function loadKeysFromVault() {
        try {
            const db  = await getPGPDB();
            const tx  = db.transaction([PGP_STORE], 'readonly');
            const all = await idbReq(tx.objectStore(PGP_STORE).getAll());
            return all.reverse(); // newest first
        } catch (e) {
            console.error('PGP: loadKeysFromVault failed:', e);
            return [];
        }
    }

    async function markPublished(id) {
        const db = await getPGPDB();
        const tx = db.transaction([PGP_STORE], 'readwrite');
        const st = tx.objectStore(PGP_STORE);
        const rec = await idbReq(st.get(id));
        if (rec) {
            rec.published   = true;
            rec.publishedAt = new Date().toISOString();
            await idbReq(st.put(rec));
        }
        await idbTx(tx);
    }

    async function deleteKeyFromVault(id) {
        const db = await getPGPDB();
        const tx = db.transaction([PGP_STORE], 'readwrite');
        tx.objectStore(PGP_STORE).delete(id);
        await idbTx(tx);
    }

    // ── Form validation ───────────────────────────────────────────────────────

    function validateForm() {
        const name       = ($('pgp-name')        || {}).value || '';
        const email      = ($('pgp-email')       || {}).value || '';
        const pass       = ($('pgp-passphrase')  || {}).value || '';
        const passConf   = ($('pgp-passphrase2') || {}).value || '';

        const errors = [];

        if (!email.trim()) {
            errors.push({ field: 'pgp-email', msg: 'Email address is required.' });
        } else if (!EMAIL_REGEX.test(email.trim())) {
            errors.push({ field: 'pgp-email', msg: 'Enter a valid email address.' });
        }

        if (pass.length < MIN_PASS_LEN) {
            errors.push({ field: 'pgp-passphrase', msg: `Passphrase must be at least ${MIN_PASS_LEN} characters.` });
        }

        if (pass !== passConf) {
            errors.push({ field: 'pgp-passphrase2', msg: 'Passphrases do not match.' });
        }

        // Clear previous errors
        document.querySelectorAll('.pgp-field-error').forEach(el => { el.textContent = ''; el.hidden = true; });
        document.querySelectorAll('.pgp-input-error').forEach(el => el.classList.remove('pgp-input-error'));

        errors.forEach(({ field, msg }) => {
            const input = $(field);
            if (input) input.classList.add('pgp-input-error');
            const errEl = $(`${field}-error`);
            if (errEl) { errEl.textContent = msg; errEl.hidden = false; }
        });

        return errors.length === 0;
    }

    function getFormValues() {
        const curve   = document.querySelector('input[name="pgp-curve"]:checked');

        return {
            name:       (($('pgp-name')       || {}).value || '').trim(),
            email:      (($('pgp-email')      || {}).value || '').trim(),
            passphrase: (($('pgp-passphrase') || {}).value || ''),
            algorithm:  'ecc',
            curve:      curve ? curve.value : 'curve25519',
            publish:    ($('pgp-publish') || {}).checked || false
        };
    }

    function algorithmLabel(values) {
        const curveLabels = {
            curve25519: 'ECC Curve25519',
            curve448:   'ECC Curve448',
            p256:       'ECC P-256',
            p384:       'ECC P-384',
            p521:       'ECC P-521'
        };
        return curveLabels[values.curve] || `ECC ${values.curve || ''}`;
    }

    // ── Passphrase strength meter ─────────────────────────────────────────────

    function updatePassStrength(passphrase) {
        const bar   = $('pgp-pass-strength-bar');
        const label = $('pgp-pass-strength-label');
        if (!bar || !label) return;

        const LABELS  = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
        const CLASSES = ['score-0', 'score-1', 'score-2', 'score-3', 'score-4'];

        if (!passphrase) {
            bar.style.width = '0%';
            CLASSES.forEach(c => { bar.classList.remove(c); label.classList.remove(c); });
            label.textContent = '';
            return;
        }

        if (typeof zxcvbn !== 'function') return;

        const result = zxcvbn(passphrase);
        const score  = result.score; // 0–4
        const pct    = Math.round((score + 1) / 5 * 100);

        bar.style.width = `${pct}%`;
        CLASSES.forEach(c => { bar.classList.remove(c); label.classList.remove(c); });
        bar.classList.add(CLASSES[score]);
        label.classList.add(CLASSES[score]);
        label.textContent = LABELS[score];
    }



    // ── Generate flow ─────────────────────────────────────────────────────────

    async function handleGenerate(e) {
        e.preventDefault();
        if (_generating) return;

        if (!validateForm()) return;

        const values = getFormValues();

        setBusy(true, 'Generating…');
        setStatus('Generating ECC key pair…');
        hideOutput();

        // SECURITY HARDENING: Clear passphrase inputs from DOM instantly
        const p1 = $('pgp-passphrase');
        const p2 = $('pgp-passphrase2');
        if (p1) p1.value = '';
        if (p2) p2.value = '';
        updatePassStrength('');

        try {
            const workerResult = await runWorker(values);

            const label = algorithmLabel(values);
            _lastResult = { ...workerResult, algorithmLabel: label };

            setStatus('Key generated! Saving to vault…');

            // Require vault master password to save private key
            const masterKey = await window.PasswordHistoryManager.getMasterKey();
            if (!masterKey) {
                // User cancelled the master password prompt — still show public key output
                setStatus('Vault save cancelled. Key is shown below but NOT saved to vault.');
                showOutput(_lastResult);
                setBusy(false);
                return;
            }

            await saveKeyToVault(_lastResult, masterKey);
            
            // SECURITY HARDENING: Wipe private key from memory immediately after saving
            if (_lastResult.privateKeyArmored) {
                _lastResult.privateKeyArmored = null;
                delete _lastResult.privateKeyArmored;
            }
            if (_lastResult.revocationCertificate) {
                _lastResult.revocationCertificate = null;
                delete _lastResult.revocationCertificate;
            }

            toast('Key pair generated and saved to vault!', true);
            setStatus('');

            showOutput(_lastResult);
            await renderKeysList();

            // Optionally publish to keyserver
            if (values.publish) {
                showPublishConfirmModal(_lastResult);
            }

        } catch (err) {
            console.error('PGP generate failed:', err);
            const msg = err && err.message ? err.message : 'Key generation failed — see console.';
            setStatus('');
            toast(msg);
        } finally {
            setBusy(false);
        }
    }

    // ── Keyserver publish confirm modal ───────────────────────────────────────
    // Reuses the existing .modal-overlay / .modal-sheet pattern from history.js

    function showPublishConfirmModal(result) {
        // Remove any existing modal
        const existing = $('pgp-publish-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id        = 'pgp-publish-modal';
        overlay.className = 'modal-overlay confirm-modal-overlay';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'pgp-publish-modal-title');
        overlay.setAttribute('aria-describedby', 'pgp-publish-modal-desc');

        const fp = formatFingerprint(result.fingerprint || '');

        overlay.innerHTML = `
          <div class="modal-sheet modal-sheet--sm">
            <div class="modal-drag-handle" aria-hidden="true"></div>
            <div class="modal-head">
              <h2 id="pgp-publish-modal-title">Publish Public Key?</h2>
            </div>
            <div class="modal-body">
              <div class="pgp-publish-warning-banner" role="alert">
                <span class="pgp-warning-icon" aria-hidden="true">⚠️</span>
                <div>
                  <strong>Read before publishing</strong>
                  <ul class="pgp-warning-list">
                    <li>Your <strong>public key</strong> will be uploaded to <code>keys.openpgp.org</code>.</li>
                    <li>Publishing is <strong>permanent</strong> — keys cannot be deleted from public keyservers.</li>
                    <li>A verification email will be sent to <strong>${escapeHtml(result.publicKeyArmored ? extractEmail(result.publicKeyArmored) : '')}.</strong></li>
                    <li>Your <strong>private key never leaves this device</strong>.</li>
                    <li>Only the public key is transmitted.</li>
                  </ul>
                </div>
              </div>
              <dl class="pgp-publish-dl">
                <dt>Fingerprint</dt>
                <dd><code class="pgp-fingerprint-sm">${escapeHtml(fp)}</code></dd>
                <dt>Key ID</dt>
                <dd><code>${escapeHtml(result.keyId || '—')}</code></dd>
                <dt>Algorithm</dt>
                <dd>${escapeHtml(result.algorithmLabel || '—')}</dd>
              </dl>
              <div class="confirm-modal-actions">
                <button class="ghost-btn" id="pgp-publish-cancel-btn">Cancel</button>
                <button class="generate-btn" id="pgp-publish-ok-btn">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                  </svg>
                  Publish Public Key
                </button>
              </div>
            </div>
          </div>`;

        document.body.appendChild(overlay);
        requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('show')));

        const dur = window.matchMedia('(prefers-reduced-motion:reduce)').matches ? 0 : 400;

        function close(confirmed) {
            overlay.classList.remove('show');
            setTimeout(() => overlay.remove(), dur);
            if (confirmed) doPublish(result);
        }

        overlay.querySelector('#pgp-publish-cancel-btn').addEventListener('click', () => close(false));
        overlay.querySelector('#pgp-publish-ok-btn').addEventListener('click',    () => close(true));
        overlay.addEventListener('click',   e => { if (e.target === overlay) close(false); });
        overlay.addEventListener('keydown', e => { if (e.key === 'Escape') close(false); });

        setTimeout(() => overlay.querySelector('#pgp-publish-cancel-btn').focus(), 80);
    }

    function extractEmail(publicKeyArmored) {
        // Quick regex to pull email from armored key header comment — not used for security
        const match = publicKeyArmored && publicKeyArmored.match(/<([^>]+)>/);
        return match ? match[1] : '';
    }

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    async function doPublish(result) {
        if (!window.KeyserverService) {
            toast('KeyserverService not available.');
            return;
        }

        setStatus('Uploading public key to keys.openpgp.org…');
        const publishBtn = $('pgp-publish-btn');
        if (publishBtn) { publishBtn.disabled = true; }

        try {
            const uploadResult = await window.KeyserverService.uploadPublicKey(result.publicKeyArmored);

            if (!uploadResult.success) {
                toast(uploadResult.error || 'Upload failed.');
                setStatus('');
                return;
            }

            // Optionally request email verification for the addresses on the key
            const email = extractEmail(result.publicKeyArmored);
            if (email && uploadResult.token) {
                await window.KeyserverService.requestEmailVerification(
                    uploadResult.token,
                    [email]
                );
                toast(`Public key published! Verification email sent to ${email}.`, true);
            } else {
                toast('Public key published to keys.openpgp.org!', true);
            }

            // Mark as published in vault
            if (result._vaultId) {
                try { await markPublished(result._vaultId); } catch (_) {}
            }

            setStatus('');
            updateKeyserverStatus('published', email);
        } catch (err) {
            console.error('PGP publish failed:', err);
            toast((err && err.message) || 'Publish failed — see console.');
            setStatus('');
        } finally {
            if (publishBtn) publishBtn.disabled = false;
        }
    }

    function updateKeyserverStatus(status, email) {
        const el = $('pgp-keyserver-status');
        if (!el) return;
        el.className = 'pgp-keyserver-status pgp-keyserver-status--published';
        el.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
            <path d="M20 6L9 17l-5-5"/>
          </svg>
          Public key published. Verification email sent to <strong>${escapeHtml(email)}</strong>.`;
        el.hidden = false;
    }

    // ── Copy public key ───────────────────────────────────────────────────────

    async function copyPublicKey() {
        const ta = $('pgp-out-pubkey');
        if (!ta || !ta.value) { toast('No public key to copy.'); return; }
        try {
            await navigator.clipboard.writeText(ta.value);
            toast('Public key copied to clipboard!', true);
        } catch {
            toast('Copy failed — select and copy manually.');
        }
    }

    // ── Keys vault list ───────────────────────────────────────────────────────

    async function renderKeysList() {
        const listEl = $('pgp-keys-list');
        if (!listEl) return;

        const keys = await loadKeysFromVault();
        listEl.innerHTML = '';

        if (keys.length === 0) {
            listEl.innerHTML = `
              <div class="pgp-empty-state">
                <span aria-hidden="true">🔑</span>
                <span>No PGP keys saved yet — generate one above.</span>
              </div>`;
            return;
        }

        keys.forEach(rec => {
            const item = document.createElement('div');
            item.className = 'pgp-key-item';
            item.innerHTML = `
              <div class="pgp-key-item-header">
                <code class="pgp-key-fp">${escapeHtml(formatFingerprint(rec.fingerprint || ''))}</code>
                <span class="pgp-key-algo">${escapeHtml(rec.algorithmLabel || '—')}</span>
              </div>
              <div class="pgp-key-item-meta">
                <span>Created: ${rec.createdAt ? new Date(rec.createdAt).toLocaleDateString() : '—'}</span>
                <span class="pgp-key-pub-badge${rec.published ? ' pgp-key-pub-badge--published' : ''}">
                  ${rec.published ? '✓ Published' : 'Local only'}
                </span>
              </div>
              <div class="pgp-key-item-actions">
                <button class="ghost-btn pgp-key-copy-btn" data-id="${rec.id}" title="Copy public key" aria-label="Copy public key">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                  Copy public key
                </button>
                ${!rec.published ? `
                <button class="ghost-btn pgp-key-publish-btn" data-id="${rec.id}" title="Publish to keyserver" aria-label="Publish to keyserver">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                  </svg>
                  Publish
                </button>` : ''}
                <button class="ghost-btn danger pgp-key-delete-btn" data-id="${rec.id}" title="Delete key" aria-label="Delete key from vault">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>
                  </svg>
                  Delete
                </button>
              </div>`;
            listEl.appendChild(item);
        });
    }

    async function handleKeysListClick(e) {
        const copyBtn    = e.target.closest('.pgp-key-copy-btn');
        const publishBtn = e.target.closest('.pgp-key-publish-btn');
        const deleteBtn  = e.target.closest('.pgp-key-delete-btn');

        if (copyBtn) {
            const id  = parseInt(copyBtn.dataset.id, 10);
            const db  = await getPGPDB();
            const tx  = db.transaction([PGP_STORE], 'readonly');
            const rec = await idbReq(tx.objectStore(PGP_STORE).get(id));
            if (rec && rec.publicKeyArmored) {
                try {
                    await navigator.clipboard.writeText(rec.publicKeyArmored);
                    toast('Public key copied!', true);
                } catch { toast('Copy failed.'); }
            }
        }

        if (publishBtn) {
            const id  = parseInt(publishBtn.dataset.id, 10);
            const db  = await getPGPDB();
            const tx  = db.transaction([PGP_STORE], 'readonly');
            const rec = await idbReq(tx.objectStore(PGP_STORE).get(id));
            if (rec) {
                showPublishConfirmModal({ ...rec, _vaultId: id });
            }
        }

        if (deleteBtn) {
            const id = parseInt(deleteBtn.dataset.id, 10);
            showDeleteConfirmModal(id);
        }
    }

    function showDeleteConfirmModal(id) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay confirm-modal-overlay';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'pgp-del-modal-title');

        overlay.innerHTML = `
          <div class="modal-sheet modal-sheet--sm">
            <div class="modal-drag-handle" aria-hidden="true"></div>
            <div class="modal-head">
              <h2 id="pgp-del-modal-title">Delete PGP Key?</h2>
            </div>
            <div class="modal-body">
              <p class="modal-desc">
                This will permanently remove the key and its encrypted private key from your vault.
                <strong>This cannot be undone.</strong> The key will remain on any keyservers it was published to.
              </p>
              <div class="confirm-modal-actions">
                <button class="ghost-btn" id="pgp-del-cancel">Cancel</button>
                <button class="generate-btn danger-btn" id="pgp-del-ok">Delete</button>
              </div>
            </div>
          </div>`;

        document.body.appendChild(overlay);
        requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('show')));
        const dur = window.matchMedia('(prefers-reduced-motion:reduce)').matches ? 0 : 400;

        function close(confirmed) {
            overlay.classList.remove('show');
            setTimeout(() => overlay.remove(), dur);
            if (confirmed) {
                deleteKeyFromVault(id)
                    .then(() => { toast('Key deleted from vault.', true); renderKeysList(); })
                    .catch(err => { console.error(err); toast('Delete failed.'); });
            }
        }

        overlay.querySelector('#pgp-del-cancel').addEventListener('click', () => close(false));
        overlay.querySelector('#pgp-del-ok').addEventListener('click',    () => close(true));
        overlay.addEventListener('click',   e => { if (e.target === overlay) close(false); });
        overlay.addEventListener('keydown', e => { if (e.key === 'Escape') close(false); });
        setTimeout(() => overlay.querySelector('#pgp-del-cancel').focus(), 80);
    }

    // ── Publish from output panel ─────────────────────────────────────────────

    function handleOutputPublish() {
        if (!_lastResult) { toast('No key generated yet.'); return; }
        showPublishConfirmModal(_lastResult);
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    async function init() {
        const form = $('pgp-form');
        if (!form) return; // Keys tab not in DOM

        form.addEventListener('submit', handleGenerate);



        // Passphrase strength meter
        const passInput = $('pgp-passphrase');
        if (passInput) {
            passInput.addEventListener('input', () => updatePassStrength(passInput.value));
        }

        // Copy public key button (output panel)
        const copyPubBtn = $('pgp-copy-pubkey-btn');
        if (copyPubBtn) copyPubBtn.addEventListener('click', copyPublicKey);

        // Publish button (output panel)
        const publishBtn = $('pgp-publish-btn');
        if (publishBtn) publishBtn.addEventListener('click', handleOutputPublish);

        // Keys list
        const listEl = $('pgp-keys-list');
        if (listEl) listEl.addEventListener('click', handleKeysListClick);

        // Load existing keys into the list
        await renderKeysList();
    }

    return { init };
})();

document.addEventListener('DOMContentLoaded', PGPManager.init);
window.PGPManager = PGPManager;
