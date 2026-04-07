/**
 * history.js — Starpass v2.2
 *
 * Architecture:
 *  - ONE master password per vault, set on first save
 *  - Master record (meta store, id=1) stores: salt + encrypted known-plaintext
 *    so we can verify the password is correct without storing it
 *  - Derived key (CryptoKey, unexportable) is cached in memory — NOT the password string
 *    This means PBKDF2 runs ONCE per session auth, then all ops are fast AES-GCM
 *  - Each entry uses the master key with a unique random IV (standard vault model)
 *  - PBKDF2-HMAC-SHA-512, 250,000 iterations
 *  - Everything lives in IndexedDB — nothing touches a server
 *  - MAX_HISTORY = 100, oldest entries auto-pruned
 *
 * Master password persistence:
 *  The SALT is stored in IndexedDB → the same password always produces the same key.
 *  After a page refresh you re-enter the password once ("Remember session" caches
 *  the derived CryptoKey for 30 min so repeat operations are instant).
 */
const PasswordHistoryManager = (() => {
    const DB_NAME      = 'StarpassDB';
    const DB_VERSION   = 3;             // incremented for new schema
    const STORE_NAME   = 'history';
    const META_STORE   = 'meta';
    const MAX_HISTORY  = 100;
    const SESSION_MINS = 30;
    const PBKDF2_ITERS = 250_000;
    const VERIFY_PLAIN = 'starpass-v2-verify';

    let db = null;

    // Cache the CryptoKey object (unexportable), not the passphrase string
    let _cachedKey    = null;
    let _keyExpiry    = null;

    // ── DB ────────────────────────────────────────────────────────────────────
    async function initDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = e => {
                const d = e.target.result;
                if (!d.objectStoreNames.contains(STORE_NAME))
                    d.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
                if (!d.objectStoreNames.contains(META_STORE))
                    d.createObjectStore(META_STORE, { keyPath: 'id' });
            };
            req.onsuccess = e => { db = e.target.result; resolve(); };
            req.onerror   = e => reject('DB: ' + e.target.error);
        });
    }

    // ── Crypto ────────────────────────────────────────────────────────────────
    async function deriveKey(passphrase, salt) {
        const raw = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(passphrase),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-512' },
            raw,
            { name: 'AES-GCM', length: 256 },
            false,                      // NOT extractable — can't be read from memory
            ['encrypt', 'decrypt']
        );
    }

    async function aesEncrypt(plaintext, key) {
        const iv   = crypto.getRandomValues(new Uint8Array(12));
        const data = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            new TextEncoder().encode(plaintext)
        );
        return { iv, encryptedData: data };
    }

    async function aesDecrypt(iv, encryptedData, key) {
        const buf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encryptedData
        );
        return new TextDecoder().decode(buf);
    }

    // ── Master key record ─────────────────────────────────────────────────────
    async function getMasterRecord() {
        const tx = db.transaction([META_STORE], 'readonly');
        return idbReq(tx.objectStore(META_STORE).get(1));
    }

    async function hasMasterPassword() {
        const rec = await getMasterRecord();
        return !!rec;
    }

    /**
     * Derives and verifies the master key.
     * On first call (no record): creates the master record and returns the key.
     * On subsequent calls: verifies against stored record, throws 'incorrect-password' if wrong.
     */
    async function deriveAndVerify(passphrase) {
        const record = await getMasterRecord();

        if (!record) {
            // First time — create master record
            const salt = crypto.getRandomValues(new Uint8Array(32));
            const key  = await deriveKey(passphrase, salt);
            const { iv, encryptedData } = await aesEncrypt(VERIFY_PLAIN, key);
            const tx = db.transaction([META_STORE], 'readwrite');
            await idbReq(tx.objectStore(META_STORE).put({ id: 1, salt, iv, encryptedData }));
            await idbTx(tx);
            return key;
        }

        // Verify existing master record
        const key = await deriveKey(passphrase, record.salt);
        try {
            const plain = await aesDecrypt(record.iv, record.encryptedData, key);
            if (plain !== VERIFY_PLAIN) throw new Error('mismatch');
            return key;
        } catch {
            throw new Error('incorrect-password');
        }
    }

    // ── Key cache (CryptoKey, not string) ─────────────────────────────────────
    function getCachedKey()  { return (_cachedKey && _keyExpiry > Date.now()) ? _cachedKey : null; }
    function setCachedKey(k) { _cachedKey = k; _keyExpiry = Date.now() + SESSION_MINS * 60_000; }
    function clearKeyCache() { _cachedKey = null; _keyExpiry = null; }

    // ── Toast ──────────────────────────────────────────────────────────────────
    function toast(msg, ok = false) {
        const c = document.getElementById('toast-container');
        if (!c) return;
        const t = document.createElement('div');
        t.className   = `toast ${ok ? 'success' : 'error'}`;
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => t.remove(), 3200);
    }

    // ── Loading indicator on the history panel ─────────────────────────────────
    function setLoading(on) {
        const list = document.getElementById('historyList');
        if (!list) return;
        if (on) {
            list.dataset.loading = 'true';
            // Add spinner if not already there
            if (!list.querySelector('.history-spinner')) {
                const s = document.createElement('div');
                s.className = 'history-spinner';
                s.setAttribute('aria-live', 'polite');
                s.textContent = '🔑 Deriving key…';
                list.prepend(s);
            }
        } else {
            delete list.dataset.loading;
            list.querySelectorAll('.history-spinner').forEach(el => el.remove());
        }
    }

    // ── Get master key: cache-first, then prompt ───────────────────────────────
    async function getMasterKey() {
        const cached = getCachedKey();
        if (cached) return cached;

        if (typeof showPassphraseModal !== 'function') {
            toast('UI module not loaded.');
            return null;
        }

        return new Promise(resolve => {
            showPassphraseModal(async (passphrase, remember) => {
                if (!passphrase) { resolve(null); return; }

                setLoading(true);
                try {
                    const key = await deriveAndVerify(passphrase);
                    if (remember) setCachedKey(key);
                    resolve(key);
                } catch (err) {
                    setLoading(false);
                    if (err.message === 'incorrect-password') {
                        toast('Wrong master password.');
                    } else {
                        console.error('Key derivation failed:', err);
                        toast('Key derivation failed.');
                    }
                    resolve(null);
                } finally {
                    setLoading(false);
                }
            });
        });
    }

    // ── IDB helpers ────────────────────────────────────────────────────────────
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

    // ── History limit ──────────────────────────────────────────────────────────
    async function enforceLimit() {
        const tx  = db.transaction([STORE_NAME], 'readwrite');
        const st  = tx.objectStore(STORE_NAME);
        const all = await idbReq(st.getAll());
        if (all.length >= MAX_HISTORY) {
            all.sort((a, b) => a.id - b.id)
               .slice(0, all.length - MAX_HISTORY + 1)
               .forEach(item => st.delete(item.id));
            await idbTx(tx);
        }
    }

    // ── Public: addToHistory ───────────────────────────────────────────────────
    async function addToHistory(value, type) {
        if (!value) { toast('Nothing to save.'); return; }
        if (!db)    { toast('Database not ready.'); return; }

        const key = await getMasterKey();
        if (!key) { toast('Save cancelled.'); return; }

        try {
            await enforceLimit();
            const { iv, encryptedData } = await aesEncrypt(value, key);
            const tx = db.transaction([STORE_NAME], 'readwrite');
            await idbReq(tx.objectStore(STORE_NAME).add({
                type, iv, encryptedData, timestamp: new Date()
            }));
            await idbTx(tx);
            toast('Saved!', true);
            loadAndDisplay();
        } catch (err) {
            console.error('Save failed:', err);
            toast('Save failed — see console.');
        }
    }

    // ── Render ──────────────────────────────────────────────────────────────────
    async function loadAndDisplay(search = '') {
        if (!db) return;
        const list = document.getElementById('historyList');
        if (!list) return;
        const existingEmptyState = list.querySelector('#history-empty-state');

        try {
            const tx  = db.transaction([STORE_NAME], 'readonly');
            const all = await idbReq(tx.objectStore(STORE_NAME).getAll());

            // Caption
            const caption = document.getElementById('history-caption');
            if (caption) {
                const hasMaster = await hasMasterPassword();
                caption.textContent = hasMaster
                    ? `${all.length} / ${MAX_HISTORY} entries · 🔒 vault active`
                    : `${all.length} / ${MAX_HISTORY} entries`;
            }

            const term    = search.toLowerCase();
            const records = all.reverse().filter(item =>
                !term ||
                item.type.toLowerCase().includes(term) ||
                new Date(item.timestamp).toLocaleDateString().includes(term)
            );

            list.innerHTML = '';
            let emptyState = existingEmptyState;
            if (!emptyState) {
                emptyState = document.createElement('div');
                emptyState.id = 'history-empty-state';
                emptyState.className = 'history-empty';
                const icon = document.createElement('span');
                icon.setAttribute('aria-hidden', 'true');
                icon.textContent = '🗂️';
                const text = document.createElement('span');
                text.textContent = 'No saved passwords yet — generate one and click Save';
                emptyState.appendChild(icon);
                emptyState.appendChild(document.createTextNode(' '));
                emptyState.appendChild(text);
            }
            emptyState.hidden = true;
            list.appendChild(emptyState);

            if (records.length === 0) {
                emptyState.hidden = false;
                return;
            }

            records.forEach(item => {
                const el = document.createElement('div');
                el.className = 'history-item';
                el.setAttribute('role', 'listitem');
                el.innerHTML = `
                    <span class="history-badge">${esc(item.type)}</span>
                    <span class="history-value" data-shown="false" data-id="${item.id}">••••••••</span>
                    <span class="history-date">${new Date(item.timestamp).toLocaleDateString()}</span>
                    <button class="history-action view-btn" data-id="${item.id}" title="Reveal / hide" aria-label="Reveal or hide">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" pointer-events="none" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                    <button class="history-action delete-btn" data-id="${item.id}" title="Delete entry" aria-label="Delete entry">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" pointer-events="none" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                    </button>
                `;
                list.appendChild(el);
            });
        } catch (err) {
            console.error('Load history failed:', err);
        }
    }

    // ── Actions ────────────────────────────────────────────────────────────────
    async function handleClick(e) {
        // Walk up from exact click target to find the action button
        const btn = e.target.closest('.history-action');
        if (!btn) return;

        const id = parseInt(btn.dataset.id, 10);
        if (!Number.isFinite(id)) return;

        if (btn.classList.contains('delete-btn')) {
            await deleteItem(id, btn);
        } else if (btn.classList.contains('view-btn')) {
            const row     = btn.closest('.history-item');
            const valueEl = row ? row.querySelector('.history-value') : null;
            if (!valueEl) return;

            // Toggle: if shown, hide it immediately (no key needed)
            if (valueEl.dataset.shown === 'true') {
                valueEl.textContent   = '••••••••';
                valueEl.dataset.shown = 'false';
                btn.setAttribute('aria-label', 'Reveal or hide');
                return;
            }
            await viewItem(id, valueEl, btn);
        }
    }

    async function deleteItem(id, btn) {
        // Disable button to prevent double-click
        btn.disabled = true;

        // Require master key before delete (prevents accidental deletion without auth)
        const key = await getMasterKey();
        if (!key) { btn.disabled = false; return; }

        try {
            const tx = db.transaction([STORE_NAME], 'readwrite');
            tx.objectStore(STORE_NAME).delete(id);
            await idbTx(tx);
            toast('Entry deleted.', true);
            loadAndDisplay();
        } catch (err) {
            console.error('Delete failed:', err);
            toast('Delete failed.');
            btn.disabled = false;
        }
    }

    async function viewItem(id, valueEl, btn) {
        btn.disabled = true;

        const key = await getMasterKey();
        if (!key) { btn.disabled = false; return; }

        try {
            const tx   = db.transaction([STORE_NAME], 'readonly');
            const item = await idbReq(tx.objectStore(STORE_NAME).get(id));
            if (!item) { toast('Item not found.'); btn.disabled = false; return; }

            const plain = await aesDecrypt(item.iv, item.encryptedData, key);
            valueEl.textContent   = plain;
            valueEl.dataset.shown = 'true';
            btn.setAttribute('aria-label', 'Hide');
        } catch (err) {
            console.error('Decrypt failed:', err);
            clearKeyCache();
            toast('Decryption failed — wrong password or corrupted entry.');
        } finally {
            btn.disabled = false;
        }
    }

    function clearAll() {
        if (!confirm('Delete ALL history and reset the vault? This cannot be undone.')) return;
        clearKeyCache();

        const tx1 = db.transaction([STORE_NAME], 'readwrite');
        tx1.objectStore(STORE_NAME).clear();
        tx1.oncomplete = () => {
            const tx2 = db.transaction([META_STORE], 'readwrite');
            tx2.objectStore(META_STORE).clear();
            tx2.oncomplete = () => { toast('Vault cleared.', true); loadAndDisplay(); };
        };
    }

    function esc(s) {
        return String(s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── Init ───────────────────────────────────────────────────────────────────
    async function init() {
        try {
            await initDB();
            await loadAndDisplay();

            const list     = document.getElementById('historyList');
            const clearBtn = document.getElementById('clear-history-button');
            const search   = document.getElementById('history-search');

            if (list)     list.addEventListener('click', handleClick);
            if (clearBtn) clearBtn.addEventListener('click', clearAll);
            if (search) {
                let timer;
                search.addEventListener('input', () => {
                    clearTimeout(timer);
                    timer = setTimeout(() => loadAndDisplay(search.value.trim()), 250);
                });
            }
        } catch (err) {
            console.error('PasswordHistoryManager init failed:', err);
        }
    }

    return { init, addToHistory };
})();

document.addEventListener('DOMContentLoaded', () => PasswordHistoryManager.init());
window.PasswordHistoryManager = PasswordHistoryManager;
