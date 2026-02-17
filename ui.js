/**
 * ui.js — Starpass v2.2
 * Passphrase modal controller
 */

function sanitizeInput(value) {
    // Allow all printable ASCII only
    return String(value).replace(/[^\x20-\x7E]/g, '');
}

function showPassphraseModal(callback) {
    if (typeof callback !== 'function') return;

    const overlay      = document.getElementById('passphrase-modal');
    const input        = document.getElementById('passphrase-input');
    const remember     = document.getElementById('remember-passphrase');
    const submitBtn    = document.getElementById('submit-passphrase');
    const clearBtn     = document.getElementById('clear-passphrase');
    const cancelBtn    = document.getElementById('cancel-passphrase');

    // Graceful fallback if modal DOM is absent
    if (!overlay || !input || !remember || !submitBtn || !clearBtn || !cancelBtn) {
        const fp = prompt('Enter master password:');
        callback(fp ? sanitizeInput(fp.trim()) : null, false);
        return;
    }

    // Reset
    input.value      = '';
    remember.checked = false;

    // Inline error slot
    let errEl = overlay.querySelector('.modal-inline-error');
    if (!errEl) {
        errEl = document.createElement('p');
        errEl.className = 'modal-inline-error';
        errEl.style.cssText = 'display:none;color:#f87171;font-size:.8125rem;margin-top:-4px;';
        errEl.setAttribute('aria-live', 'polite');
        input.insertAdjacentElement('afterend', errEl);
    }
    errEl.style.display = 'none';
    errEl.textContent   = '';

    // Open: remove hidden first so element enters layout, then rAF for transition
    overlay.classList.remove('hidden');
    requestAnimationFrame(() => {
        requestAnimationFrame(() => overlay.classList.add('show'));
    });

    // Lock background scroll
    document.body.style.overflow = 'hidden';

    // Focus input after animation starts
    setTimeout(() => input.focus(), 80);

    // Focus trap
    const focusable = overlay.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    const firstEl = focusable[0];
    const lastEl  = focusable[focusable.length - 1];

    // ── Helpers ──────────────────────────────────────────────────────────
    function showError(msg) {
        errEl.textContent   = msg;
        errEl.style.display = 'block';
        clearTimeout(errEl._t);
        errEl._t = setTimeout(() => { errEl.style.display = 'none'; }, 4000);
    }

    function close(passphrase, rem) {
        overlay.classList.remove('show');
        document.body.style.overflow = '';
        // Wait for CSS transition to finish before hiding from layout
        const dur = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 400;
        setTimeout(() => overlay.classList.add('hidden'), dur);
        cleanup();
        callback(passphrase, rem);
    }

    // ── Handlers ─────────────────────────────────────────────────────────
    function onSubmit() {
        const val = sanitizeInput(input.value.trim());
        if (!val) { showError('Please enter your master password.'); input.focus(); return; }
        close(val, remember.checked);
    }

    function onCancel()  { close(null, false); }
    function onClear()   { input.value = ''; input.focus(); }

    function onKeydown(e) {
        if (e.key === 'Escape') { e.preventDefault(); onCancel(); return; }
        if (e.key === 'Tab') {
            if (e.shiftKey && document.activeElement === firstEl) {
                e.preventDefault(); lastEl.focus();
            } else if (!e.shiftKey && document.activeElement === lastEl) {
                e.preventDefault(); firstEl.focus();
            }
        }
    }

    function onInputKey(e) { if (e.key === 'Enter') { e.preventDefault(); onSubmit(); } }
    function onBackdrop(e) { if (e.target === overlay) onCancel(); }

    // ── Listeners ─────────────────────────────────────────────────────────
    function cleanup() {
        submitBtn.removeEventListener('click',   onSubmit);
        cancelBtn.removeEventListener('click',   onCancel);
        clearBtn.removeEventListener('click',    onClear);
        input.removeEventListener('keydown',     onInputKey);
        overlay.removeEventListener('keydown',   onKeydown);
        overlay.removeEventListener('click',     onBackdrop);
    }

    submitBtn.addEventListener('click',  onSubmit);
    cancelBtn.addEventListener('click',  onCancel);
    clearBtn.addEventListener('click',   onClear);
    input.addEventListener('keydown',    onInputKey);
    overlay.addEventListener('keydown',  onKeydown);
    overlay.addEventListener('click',    onBackdrop);
}
