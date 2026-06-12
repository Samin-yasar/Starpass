/**
 * pgp.worker.js — Starpass Phase 3
 *
 * Runs inside a Web Worker so heavy key generation never blocks the main thread.
 * Loaded via: new Worker('src/workers/pgp.worker.js')
 *
 * Messages IN  → { type: 'GENERATE', payload: { curve, name, email, passphrase } }
 * Messages OUT → { type: 'PROGRESS', payload: { message } }
 *              → { type: 'SUCCESS',  payload: { publicKeyArmored, privateKeyArmored, revocationCertificate, fingerprint, keyId, createdAt } }
 *              → { type: 'ERROR',    payload: { code, message } }
 *
 * IMPORTANT: Uses importScripts (not ES module import) — this project has no bundler.
 * The openpgp.min.js IIFE build exposes `globalThis.openpgp` after importScripts.
 */

/* global openpgp */

// Path is relative to the HTML page origin, not this worker file's location.
// The worker URL is resolved from the page, so 'src/openpgp.min.js' works.
// However, importScripts paths are relative to the worker script itself.
// This worker is at src/workers/pgp.worker.js, so ../openpgp.min.js resolves to src/openpgp.min.js.
try {
    importScripts('../openpgp.min.js');
} catch (e) {
    self.postMessage({
        type: 'ERROR',
        payload: {
            code: 'WORKER_LOAD_FAILED',
            message: 'Failed to load openpgp.js library: ' + (e && e.message ? e.message : String(e))
        }
    });
    // Cannot proceed without the library
    throw e;
}

// ── Classify errors into stable codes ────────────────────────────────────────
function classifyError(err) {
    const msg = err && err.message ? err.message.toLowerCase() : '';

    if (msg.includes('invalid user id')) return 'INVALID_USER_ID';
    if (msg.includes('passphrase') || msg.includes('password')) return 'WEAK_PASSPHRASE';
    if (msg.includes('unsupported') || msg.includes('not supported')) return 'UNSUPPORTED_ALGORITHM';
    if (msg.includes('cancel') || msg.includes('abort')) return 'GENERATION_CANCELLED';
    if (msg.includes('out of memory') || msg.includes('memory')) return 'OUT_OF_MEMORY';
    if (msg.includes('timeout')) return 'GENERATION_TIMEOUT';

    return 'GENERATION_FAILED';
}

// ── Build openpgp key generation options ─────────────────────────────────────
function buildKeyOptions(payload) {
    const { curve, name, email, passphrase } = payload;

    // userIDs is required by openpgp — even a blank name is acceptable
    const userIDs = [{ name: (name || '').trim(), email: (email || '').trim() }];

    // Default: ECC (ecc) — curve25519 or curve448
    const validCurves = ['curve25519', 'curve448', 'p256', 'p384', 'p521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1'];
    const chosenCurve = validCurves.includes(curve) ? curve : 'curve25519';

    return {
        type: 'ecc',
        curve: chosenCurve,
        userIDs,
        passphrase,
        format: 'armored'
    };
}

// ── Parse fingerprint and keyId from armored public key ──────────────────────
async function parseKeyMeta(publicKeyArmored) {
    try {
        const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const fp = key.getFingerprint();                 // hex string (lowercase)
        const kid = key.getKeyID().toHex();              // 16-char hex
        const created = key.getCreationTime();           // Date object
        return {
            fingerprint: fp.toUpperCase(),
            keyId:       kid.toUpperCase(),
            createdAt:   created instanceof Date ? created.toISOString() : new Date().toISOString()
        };
    } catch (e) {
        // Non-fatal — caller can handle missing meta
        return {
            fingerprint: null,
            keyId:       null,
            createdAt:   new Date().toISOString()
        };
    }
}

// ── Message handler ───────────────────────────────────────────────────────────
self.addEventListener('message', async (evt) => {
    const { type, payload } = evt.data || {};

    if (type !== 'GENERATE') {
        self.postMessage({
            type: 'ERROR',
            payload: { code: 'UNKNOWN_MESSAGE', message: `Unknown message type: ${type}` }
        });
        return;
    }

    // Basic validation before handing off to openpgp
    if (!payload || !payload.email) {
        self.postMessage({
            type: 'ERROR',
            payload: { code: 'INVALID_PAYLOAD', message: 'email is required to generate a PGP key.' }
        });
        return;
    }

    if (!payload.passphrase || payload.passphrase.length < 12) {
        self.postMessage({
            type: 'ERROR',
            payload: { code: 'WEAK_PASSPHRASE', message: 'Key passphrase must be at least 12 characters.' }
        });
        return;
    }

    // Notify UI that we're starting
    self.postMessage({ type: 'PROGRESS', payload: { message: 'Generating key pair…' } });

    try {
        const options = buildKeyOptions(payload);
        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey(options);

        // Parse metadata from the public key
        self.postMessage({ type: 'PROGRESS', payload: { message: 'Parsing key metadata…' } });
        const meta = await parseKeyMeta(publicKey);

        self.postMessage({
            type: 'SUCCESS',
            payload: {
                publicKeyArmored:       publicKey,
                privateKeyArmored:      privateKey,
                revocationCertificate:  revocationCertificate,
                fingerprint:            meta.fingerprint,
                keyId:                  meta.keyId,
                createdAt:              meta.createdAt
            }
        });
    } catch (err) {
        const code = classifyError(err);
        const message = (err && err.message) ? err.message : 'Key generation failed.';
        self.postMessage({ type: 'ERROR', payload: { code, message } });
    }
});
