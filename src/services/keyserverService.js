/**
 * keyserverService.js — Starpass Phase 3
 * Handles all interactions with the keys.openpgp.org VKS API.
 *
 * Public API (exposed on window.KeyserverService):
 *   uploadPublicKey(armoredPublicKey)                            → Promise<UploadResult>
 *   requestEmailVerification(token, emailAddresses)              → Promise<UploadResult>
 */

const KeyserverService = (() => {
    const VKS_BASE_URL = 'https://keys.openpgp.org';
    const UPLOAD_PATH  = '/vks/v1/upload';
    const VERIFY_PATH  = '/vks/v1/request-verify';
    const MAX_RETRIES  = 3;
    const BACKOFF_BASE = 1000;

    // ── Upload ────────────────────────────────────────────────────────────────

    /**
     * Uploads an ASCII-armored public key to keys.openpgp.org.
     * Retries with exponential backoff on transient server/network errors.
     *
     * @param {string} armoredPublicKey
     * @returns {Promise<{success:boolean, token?:string, fingerprint?:string,
     *                    status?:Object, error?:string, errorCode?:string}>}
     */
    async function uploadPublicKey(armoredPublicKey) {
        if (!armoredPublicKey || typeof armoredPublicKey !== 'string') {
            return { success: false, error: 'Invalid key data.', errorCode: 'INVALID_KEY' };
        }
        
        // Critical safety check: Ensure we never upload a private key
        if (armoredPublicKey.includes('PRIVATE KEY BLOCK') || armoredPublicKey.includes('SECRET KEY BLOCK')) {
            return {
                success: false,
                error: 'CRITICAL ERROR: Attempted to upload a private key. Upload aborted for your security.',
                errorCode: 'PRIVATE_KEY_LEAK_PREVENTED'
            };
        }

        let lastError;

        for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                await sleep(BACKOFF_BASE * Math.pow(2, attempt - 1));
            }
            try {
                return await attemptUpload(armoredPublicKey);
            } catch (err) {
                lastError = err;
                // Do NOT retry 4xx client errors — they won't resolve by retrying
                if (err.statusCode >= 400 && err.statusCode < 500) break;
            }
        }

        return {
            success:   false,
            error:     lastError?.message || 'Upload failed after maximum retries.',
            errorCode: lastError?.code    || 'UPLOAD_FAILED'
        };
    }

    async function attemptUpload(armoredPublicKey) {
        let response;
        try {
            response = await fetch(`${VKS_BASE_URL}${UPLOAD_PATH}`, {
                method:      'POST',
                headers:     { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body:        JSON.stringify({ keytext: armoredPublicKey }),
                credentials: 'omit',
                signal:      AbortSignal.timeout(30_000)
            });
        } catch {
            const err = Object.assign(
                new Error('Could not reach keys.openpgp.org. Check your internet connection.'),
                { code: 'NETWORK_ERROR' }
            );
            throw err;
        }

        let body;
        try { body = await response.json(); } catch {
            throw Object.assign(new Error('Server returned an unreadable response.'),
                { code: 'PARSE_ERROR', statusCode: response.status });
        }

        if (!response.ok) {
            throw Object.assign(new Error(interpretHttpError(response.status, body)),
                { code: `HTTP_${response.status}`, statusCode: response.status });
        }

        if (!body.token || !body.key_fpr || !body.status) {
            throw Object.assign(new Error('Server response is missing required fields.'),
                { code: 'INVALID_RESPONSE', statusCode: response.status });
        }

        return { success: true, token: body.token, fingerprint: body.key_fpr, status: body.status };
    }

    // ── Request email verification ─────────────────────────────────────────────

    /**
     * @param {string}   token
     * @param {string[]} emailAddresses
     * @param {string[]} [locale]
     */
    async function requestEmailVerification(token, emailAddresses, locale = ['en']) {
        try {
            const response = await fetch(`${VKS_BASE_URL}${VERIFY_PATH}`, {
                method:      'POST',
                headers:     { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body:        JSON.stringify({ token, addresses: emailAddresses, locale }),
                credentials: 'omit',
                signal:      AbortSignal.timeout(30_000)
            });
            const body = await response.json();
            if (!response.ok) {
                return { success: false, error: interpretHttpError(response.status, body),
                         errorCode: `HTTP_${response.status}` };
            }
            return { success: true, token: body.token, fingerprint: body.key_fpr, status: body.status };
        } catch (err) {
            return { success: false, error: err.message || 'Failed to request email verification.',
                     errorCode: err.code || 'VERIFY_REQUEST_FAILED' };
        }
    }

    // ── Error interpretation ───────────────────────────────────────────────────

    function interpretHttpError(status, body) {
        const msg = body?.error || body?.message || '';
        switch (status) {
            case 400: return `The key could not be parsed by the keyserver. ${msg}`.trim();
            case 413: return 'The key is too large to be accepted by the keyserver.';
            case 415: return 'The keyserver rejected the request format. This is a bug — please report it.';
            case 422: return `The key was rejected: ${msg || 'unprocessable key data.'}`;
            case 429: return 'Too many requests to the keyserver. Please wait a few minutes and try again.';
            case 500: case 502: case 503: case 504:
                return 'The keyserver is temporarily unavailable. Please try again later.';
            default:  return `Unexpected keyserver response (HTTP ${status}). ${msg}`.trim();
        }
    }

    // ── Utility ───────────────────────────────────────────────────────────────
    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    return { uploadPublicKey, requestEmailVerification };
})();

window.KeyserverService = KeyserverService;
