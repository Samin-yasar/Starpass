/**
 * app.js — Starpass v2.2
 *
 * Fixed:
 *  - Tab selector .tab-button → .tab-btn (matches HTML)
 *  - Crack time: custom formatter with real math, humor > 10M years
 *  - SVGs in buttons get pointer-events:none via aria-hidden pattern
 */
const StarpassApp = (() => {
    let wordList      = [];
    let zxcvbnLoaded  = false;
    let currentResult = { value: '', type: '' };

    const CHARACTER_SETS = {
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numbers:   '0123456789',
        special:   '!@#$%^&*()-_=+[]{}|;:,.<>?'
    };

    const SCORE_COLORS = ['#f87171','#fb923c','#fbbf24','#a3e635','#34d399'];
    const SCORE_LABELS = ['Very Weak','Weak','Fair','Strong','Very Strong'];

    function $(id) { return document.getElementById(id); }

    function toast(msg, success = false) {
        const c = $('toast-container');
        if (!c) return;
        const t = document.createElement('div');
        t.className   = `toast ${success ? 'success' : 'error'}`;
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => t.remove(), 3000);
    }

    function secureRandom(max) {
        if (max <= 1) return 0;
        const cap = Math.floor(0x100000000 / max) * max;
        const buf = new Uint32Array(1);
        do { crypto.getRandomValues(buf); } while (buf[0] >= cap);
        return buf[0] % max;
    }

    function shuffle(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = secureRandom(i + 1);
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }

    async function loadWordList() {
        if (wordList.length > 0) return true;
        try {
            const r = await fetch('src/common_wordslist.json');
            if (!r.ok) throw new Error('fetch failed');
            wordList = await r.json();
        } catch {
            wordList = ['apple','brave','cedar','delta','eagle','frost','grape','haste',
                        'iris','joust','kneel','lemon','maple','noble','ocean','pearl',
                        'quest','river','storm','tiger','ultra','vivid','whirl','xenon',
                        'yacht','zesty','amber','blaze','crisp','dunes'];
        }
        return true;
    }

    async function loadZxcvbn() {
        if (zxcvbnLoaded) return;
        await new Promise((resolve, reject) => {
            const s   = document.createElement('script');
            s.src     = 'src/zxcvbn.min.js';
            s.onload  = () => { zxcvbnLoaded = true; resolve(); };
            s.onerror = () => reject(new Error('zxcvbn load failed'));
            document.head.appendChild(s);
        });
    }

    // ── Crack time formatter ──────────────────────────────────────────────────
    // zxcvbn gives us raw seconds via crack_times_seconds.offline_fast_hashing_1e10_per_second
    // We format it ourselves with real math and contextual humor above 10M years.
    function formatCrackTime(seconds) {
        if (!isFinite(seconds) || seconds > 1e30) {
            return {
                main: 'effectively uncrackable',
                sub:  '🌌 The universe is ~13.8 billion years old. Even cosmic time isn\'t enough.'
            };
        }

        const s  = seconds;
        const m  = 60;
        const h  = 3600;
        const d  = 86400;
        const w  = d * 7;
        const mo = d * 30.44;
        const y  = d * 365.25;

        const n = (val, unit) => {
            const r = Math.round(val);
            return `${r.toLocaleString()} ${unit}${r !== 1 ? 's' : ''}`;
        };

        if (s < 1)    return { main: 'less than a second' };
        if (s < m)    return { main: n(s, 'second') };
        if (s < h)    return { main: n(s/m, 'minute') };
        if (s < d)    return { main: n(s/h, 'hour') };
        if (s < w)    return { main: n(s/d, 'day') };
        if (s < mo)   return { main: n(s/w, 'week') };
        if (s < y)    return { main: n(s/mo, 'month') };

        const years = s / y;

        if (years < 1e3)  return { main: n(years, 'year') };
        if (years < 1e6)  return { main: `~${(years/1e3).toFixed(1)}K years` };

        const MY = years / 1e6; // millions of years

        // Cap display at 10M years as requested; add factual context above that
        if (MY < 10)   return { main: `~${MY.toFixed(1)} million years` };

        // > 10 million years — show tiered factual context, no raw number needed
        if (MY < 66)   return {
            main: '> 10 million years',
            sub:  '🦕 The last non-avian dinosaurs went extinct ~66 million years ago — this password would still be uncracked.'
        };
        if (MY < 175)  return {
            main: 'geologic timescales',
            sub:  '🌊 The Atlantic Ocean began opening ~175 million years ago. Your password pre-dates an entire ocean.'
        };
        if (MY < 540)  return {
            main: 'pre-Cambrian timescales',
            sub:  '🐚 The Cambrian Explosion of complex life was ~540 million years ago. Your password predates eyes, brains, and skeletons.'
        };
        if (MY < 4500) return {
            main: 'older than Earth',
            sub:  '🌍 Earth formed ~4.5 billion years ago. This password would outlast the planet itself.'
        };
        return {
            main: 'older than the universe',
            sub:  '🌌 The Big Bang was ~13.8 billion years ago. Your password exists outside of time.'
        };
    }

    async function calculateStrength(password) {
        const section = $('strength-analysis');
        const barFill = $('strength-bar-fill');
        const crackEl = $('crack-time');
        const labelEl = $('strength-label');
        if (!section || !barFill || !crackEl) return;

        section.classList.remove('hidden');

        try {
            await loadZxcvbn();
            if (typeof zxcvbn !== 'function') return;

            const result = zxcvbn(password);
            const score  = result.score; // 0–4
            const pct    = Math.round((score + 1) / 5 * 100); // 20–100%

            barFill.style.width      = pct + '%';
            barFill.style.background = SCORE_COLORS[score];
            barFill.setAttribute('aria-valuenow', String(pct));

            if (labelEl) {
                labelEl.textContent  = SCORE_LABELS[score];
                labelEl.style.color  = SCORE_COLORS[score];
            }

            const rawSeconds = result.crack_times_seconds.offline_fast_hashing_1e10_per_second;
            const { main, sub } = formatCrackTime(rawSeconds);

            crackEl.innerHTML = sub
                ? `<span class="crack-time-label">Crack time:</span> <span class="crack-time-value">${main}</span><br><span class="crack-time-note">${sub}</span>`
                : `<span class="crack-time-label">Crack time:</span> <span class="crack-time-value">${main}</span>`;

        } catch (err) {
            console.error('Strength calculation failed:', err);
        }
    }

    function setResult(value, type) {
        currentResult = { value, type };
        const resultEl   = $('result');
        const outputEl   = $('output');
        const strengthEl = $('strength-analysis');

        if (resultEl)  resultEl.textContent = value;
        if (outputEl)  outputEl.classList.remove('hidden');

        if (type === 'password' || type === 'passphrase') {
            calculateStrength(value);
        } else {
            if (strengthEl) strengthEl.classList.add('hidden');
        }
    }

    // ── Modal helper ──────────────────────────────────────────────────────────
    function openModal(modalId, closeBtnId, openBtnId) {
        const modal    = $(modalId);
        const closeBtn = $(closeBtnId);
        const openBtn  = $(openBtnId);
        if (!modal) return;

        modal.classList.remove('hidden');
        requestAnimationFrame(() => requestAnimationFrame(() => modal.classList.add('show')));

        function close() {
            modal.classList.remove('show');
            const dur = window.matchMedia('(prefers-reduced-motion:reduce)').matches ? 0 : 400;
            setTimeout(() => modal.classList.add('hidden'), dur);
            if (openBtn) openBtn.focus();
            modal.removeEventListener('click',   onBackdrop);
            modal.removeEventListener('keydown', onKeydown);
            if (closeBtn) closeBtn.removeEventListener('click', close);
        }

        function onBackdrop(e) { if (e.target === modal) close(); }
        function onKeydown(e)  { if (e.key === 'Escape') close(); }

        if (closeBtn) closeBtn.addEventListener('click', close);
        modal.addEventListener('click',   onBackdrop);
        modal.addEventListener('keydown', onKeydown);
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    function init() {
        setupForms();
        setupTabs();
        setupOutputButtons();
        setupRangeDisplays();
        setupHeaderButtons();
        loadWordList();
    }

    function setupForms() {
        $('password-form').addEventListener('submit',   e => { e.preventDefault(); generatePassword();   });
        $('passphrase-form').addEventListener('submit', e => { e.preventDefault(); generatePassphrase(); });
        $('username-form').addEventListener('submit',   e => { e.preventDefault(); generateUsername();   });
    }

    function setupTabs() {
        // FIXED: selector is .tab-btn (not .tab-button) to match HTML
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-btn').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                const panel = $(tab);
                if (panel) panel.classList.add('active');
                btn.classList.add('active');
                btn.setAttribute('aria-selected', 'true');
            });
        });
    }

    function setupOutputButtons() {
        $('copy-button').addEventListener('click', async () => {
            if (!currentResult.value) return;
            try {
                await navigator.clipboard.writeText(currentResult.value);
                toast('Copied!', true);
            } catch { toast('Copy failed — try selecting manually.'); }
        });

        $('save-button').addEventListener('click', () => {
            if (!currentResult.value) { toast('Nothing to save.'); return; }
            if (window.PasswordHistoryManager) {
                PasswordHistoryManager.addToHistory(currentResult.value, currentResult.type);
            } else {
                toast('History module not available.');
            }
        });
    }

    function setupRangeDisplays() {
        ['password-length', 'word-count', 'username-length'].forEach(id => {
            const input = $(id);
            const span  = document.querySelector(`label[for="${id}"] .value-display`);
            if (input && span) {
                input.addEventListener('input', () => {
                    span.textContent = input.value;
                    input.setAttribute('aria-valuenow', input.value);
                });
            }
        });
    }

    function setupHeaderButtons() {
        const bind = (openId, modalId, closeId) => {
            const btn = $(openId);
            if (btn) btn.addEventListener('click', () => openModal(modalId, closeId, openId));
        };
        bind('changelog-button', 'changelog-modal', 'changelog-close');
        bind('help-button',      'help-modal',      'help-close');
        bind('share-button',     'share-modal',      'share-close');

        const copyUrl = $('copy-url-button');
        if (copyUrl) copyUrl.addEventListener('click', async () => {
            try { await navigator.clipboard.writeText(window.location.href); toast('Link copied!', true); }
            catch { toast('Could not copy link.'); }
        });

        const twitterBtn = $('twitter-share');
        if (twitterBtn) twitterBtn.addEventListener('click', () => {
            const text = encodeURIComponent('Starpass — free, private, zero-server password generator');
            window.open(`https://twitter.com/intent/tweet?text=${text}&url=${encodeURIComponent(location.href)}`, '_blank', 'noopener');
        });

        const emailBtn = $('email-share');
        if (emailBtn) emailBtn.addEventListener('click', () => {
            const sub  = encodeURIComponent('Starpass Password Generator');
            const body = encodeURIComponent(`Check this out:\n${location.href}`);
            location.href = `mailto:?subject=${sub}&body=${body}`;
        });
    }

    // ── Generators ────────────────────────────────────────────────────────────
    function generatePassword() {
        const length       = parseInt($('password-length').value);
        const lowerCount   = Math.max(0, parseInt($('lowercase').value) || 0);
        const upperCount   = Math.max(0, parseInt($('uppercase').value) || 0);
        const numCount     = Math.max(0, parseInt($('numbers').value)   || 0);
        const specialCount = Math.max(0, parseInt($('special').value)   || 0);
        const noAmbig      = $('exclude-ambiguous').checked;

        const sets = {
            lowercase: CHARACTER_SETS.lowercase.replace(noAmbig ? /[il]/g : /$/g, ''),
            uppercase: CHARACTER_SETS.uppercase.replace(noAmbig ? /[IO]/g : /$/g, ''),
            numbers:   CHARACTER_SETS.numbers.replace(  noAmbig ? /[01]/g : /$/g, ''),
            special:   CHARACTER_SETS.special
        };

        const minReq = lowerCount + upperCount + numCount + specialCount;
        if (minReq === 0) { toast('Set at least one character type.'); return; }

        const effLen = Math.max(length, minReq);
        const chars  = [];

        const add = (type, n) => {
            const pool = sets[type];
            if (!pool.length) return;
            for (let i = 0; i < n; i++) chars.push(pool[secureRandom(pool.length)]);
        };
        add('lowercase', lowerCount);
        add('uppercase', upperCount);
        add('numbers',   numCount);
        add('special',   specialCount);

        let fill = '';
        if (lowerCount   > 0) fill += sets.lowercase;
        if (upperCount   > 0) fill += sets.uppercase;
        if (numCount     > 0) fill += sets.numbers;
        if (specialCount > 0) fill += sets.special;

        const rem = effLen - chars.length;
        for (let i = 0; i < rem; i++) chars.push(fill[secureRandom(fill.length)]);

        setResult(shuffle(chars).join(''), 'password');
    }

    async function generatePassphrase() {
        await loadWordList();
        const wordCount  = parseInt($('word-count').value);
        const separator  = $('separator').value;
        const capitalize = $('capitalize-words').checked;
        const withNumber = $('include-number').checked;

        const words = Array.from({ length: wordCount }, () => {
            let w = wordList[secureRandom(wordList.length)];
            return capitalize ? w[0].toUpperCase() + w.slice(1) : w;
        });

        let phrase = words.join(separator);
        if (withNumber) phrase += secureRandom(100);
        setResult(phrase, 'passphrase');
    }

    async function generateUsername() {
        await loadWordList();
        const length     = parseInt($('username-length').value);
        const withNumber = $('include-number-username').checked;
        const allLower   = $('all-lowercase').checked;

        let u = '';
        while (u.length < length) u += wordList[secureRandom(wordList.length)];
        u = u.slice(0, length);

        if (withNumber) {
            const num = String(secureRandom(100)).padStart(2, '0');
            u = u.slice(0, length - num.length) + num;
        }
        if (allLower) u = u.toLowerCase();
        setResult(u, 'username');
    }

    return { init };
})();

document.addEventListener('DOMContentLoaded', StarpassApp.init);
