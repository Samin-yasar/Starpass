/**
 * Manages password history with encryption and UI updates.
 * @module PasswordHistoryManager
 */
const PasswordHistoryManager = (() => {
    const passwordHistory = [];
    const deletedItems = []; // For undo functionality
    const MAX_HISTORY = 10;
    const PBKDF2_ITERATIONS = 100000;
    const STORAGE_KEYS = {
        HISTORY: 'secureGeneratorHistory',
        ERRORS: 'errorLog'
    };
    const ERROR_MESSAGES = {
        INVALID_TYPE: 'Invalid history item type.',
        NO_PASSPHRASE: 'Please set an encryption passphrase.',
        INVALID_PASSPHRASE: 'Invalid encryption passphrase.',
        ENCRYPTION_FAILED: 'Failed to encrypt history data.',
        DECRYPTION_FAILED: 'Decryption failed. Incorrect passphrase or corrupted history.',
        SAVE_FAILED: 'Failed to save history.',
        INVALID_ENCRYPTION: 'Failed to save history due to invalid encryption.',
        STORAGE_QUOTA: 'Storage limit exceeded. Please clear history or reduce entries.',
        WEAK_PASSPHRASE: 'Passphrase is too weak. Please use a stronger passphrase.',
        RATE_LIMIT: 'Please wait before performing another action.'
    };
    const VALID_TYPES = ['password', 'pin', 'phrase'];
    let tempPassphrase = null; // Closure-based passphrase storage
    let lastActionTime = 0;
    const RATE_LIMIT_MS = 1000; // 1 second

    /**
     * Logs errors to localStorage for debugging.
     * @param {Error} error - The error object.
     * @param {string} message - The error message.
     */
    function logError(error, message) {
        const errorLog = JSON.parse(localStorage.getItem(STORAGE_KEYS.ERRORS) || '[]');
        errorLog.push({ timestamp: new Date().toISOString(), message, stack: error.stack });
        if (errorLog.length > 50) errorLog.shift();
        localStorage.setItem(STORAGE_KEYS.ERRORS, JSON.stringify(errorLog));
    }

    /**
     * Handles errors consistently across the module.
     * @param {Error} error - The error object.
     * @param {string} defaultMessage - Fallback error message.
     * @param {boolean} [isSuccess=false] - Whether the message is a success message.
     */
    function handleError(error, defaultMessage, isSuccess = false) {
        logError(error, defaultMessage);
        const messages = {
            QuotaExceededError: ERROR_MESSAGES.STORAGE_QUOTA,
            TypeError: 'Invalid input type. Please check your inputs.'
        };
        showError(messages[error.name] || defaultMessage, isSuccess);
        console.error(error);
    }

    /**
     * Throttles a function to limit execution rate.
     * @param {Function} fn - The function to throttle.
     * @returns {Function} The throttled function.
     */
    function throttle(fn) {
        return async (...args) => {
            const now = Date.now();
            if (now - lastActionTime < RATE_LIMIT_MS) {
                showError(ERROR_MESSAGES.RATE_LIMIT);
                return;
            }
            lastActionTime = now;
            return fn(...args);
        };
    }

    /**
     * Derives an encryption key from a passphrase using PBKDF2.
     * @param {string} passphrase - The passphrase to derive the key from.
     * @param {Uint8Array} salt - The salt for key derivation.
     * @returns {Promise<{key: CryptoKey, salt: Uint8Array} | null>} The derived key and salt, or null on error.
     */
    async function deriveKeyFromPassphrase(passphrase, salt) {
        try {
            const encoder = new TextEncoder();
            const passphraseKey = encoder.encode(passphrase);
            const keyMaterial = await crypto.subtle.importKey(
                'raw', passphraseKey, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
            );
            const key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            return { key, salt };
        } catch (error) {
            handleError(error, 'Failed to derive encryption key.');
            return null;
        }
    }

    /**
     * Encrypts data using AES-GCM.
     * @param {Object} data - The data to encrypt.
     * @param {string} passphrase - The encryption passphrase.
     * @returns {Promise<string | null>} The encrypted data as a base64 string, or null on error.
     */
    async function encryptData(data, passphrase) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(JSON.stringify(data));
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const keyResult = await deriveKeyFromPassphrase(passphrase, salt);
            if (!keyResult) throw new Error('Key derivation failed');
            const { key } = keyResult;
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, dataBuffer
            );
            const fullBuffer = new Uint8Array(salt.length + iv.length + encryptedBuffer.byteLength);
            fullBuffer.set(salt);
            fullBuffer.set(iv, salt.length);
            fullBuffer.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);
            return btoa(String.fromCharCode(...fullBuffer));
        } catch (error) {
            handleError(error, ERROR_MESSAGES.ENCRYPTION_FAILED);
            return null;
        }
    }

    /**
     * Decrypts data using AES-GCM.
     * @param {string} encryptedData - The encrypted data as a base64 string.
     * @param {string} passphrase - The decryption passphrase.
     * @returns {Promise<Object | null>} The decrypted data, or null on error.
     */
    async function decryptData(encryptedData, passphrase) {
        try {
            const fullBuffer = new Uint8Array([...atob(encryptedData)].map(c => c.charCodeAt(0)));
            const salt = fullBuffer.slice(0, 16);
            const iv = fullBuffer.slice(16, 28);
            const data = fullBuffer.slice(28);
            const keyResult = await deriveKeyFromPassphrase(passphrase, salt);
            if (!keyResult) return null;
            const { key } = keyResult;
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, key, data
            );
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decryptedBuffer));
        } catch (err) {
            handleError(err, ERROR_MESSAGES.DECRYPTION_FAILED);
            return null;
        }
    }

    /**
     * Saves the password history to localStorage.
     * @param {string} passphrase - The encryption passphrase.
     * @returns {Promise<void>}
     */
    async function saveHistory(passphrase) {
        try {
            const encryptedHistory = await encryptData(passwordHistory, passphrase);
            if (typeof encryptedHistory === 'string' && encryptedHistory.trim() !== '') {
                localStorage.setItem(STORAGE_KEYS.HISTORY, encryptedHistory);
            } else {
                throw new Error('Invalid encrypted history data');
            }
        } catch (error) {
            handleError(error, ERROR_MESSAGES.SAVE_FAILED);
        }
    }

    /**
     * Loads the password history from localStorage.
     * @param {string} passphrase - The decryption passphrase.
     * @returns {Promise<boolean>} True if loaded successfully, false otherwise.
     */
    async function loadHistory(passphrase) {
        const encrypted = localStorage.getItem(STORAGE_KEYS.HISTORY);
        if (!encrypted) {
            passwordHistory.length = 0;
            return false;
        }
        const decrypted = await decryptData(encrypted, passphrase);
        if (decrypted && Array.isArray(decrypted)) {
            passwordHistory.length = 0;
            passwordHistory.push(...decrypted);
            return true;
        }
        return false;
    }

    /**
     * Sanitizes input values to prevent injection or invalid characters.
     * @param {string} value - The value to sanitize.
     * @returns {string} The sanitized value.
     */
    function sanitizeValue(value) {
        return value.replace(/[<>&"']/g, '');
    }

    /**
     * Adds an item to the password history.
     * @param {string} value - The value to add.
     * @param {string} type - The type of item (password, pin, phrase).
     * @param {string} [timestamp=new Date().toISOString()] - The timestamp of the item.
     */
    const addToHistory = throttle(async (value, type, timestamp = new Date().toISOString()) => {
        if (!VALID_TYPES.includes(type)) {
            showError(ERROR_MESSAGES.INVALID_TYPE);
            return;
        }
        const sanitizedValue = sanitizeValue(value);
        showPassphraseModal(async (passphrase) => {
            if (!passphrase) {
                showError(ERROR_MESSAGES.NO_PASSPHRASE);
                return;
            }
            if (typeof zxcvbn === 'function' && zxcvbn(passphrase).score < 3) {
                showError(ERROR_MESSAGES.WEAK_PASSPHRASE);
                return;
            }
            tempPassphrase = passphrase; // Store temporarily
            const isValid = await loadHistory(passphrase);
            if (!isValid) {
                showError(ERROR_MESSAGES.INVALID_PASSPHRASE);
                tempPassphrase = null;
                return;
            }
            const historyItem = { value: sanitizedValue, type, timestamp };
            passwordHistory.unshift(historyItem);
            if (passwordHistory.length > MAX_HISTORY) {
                passwordHistory.pop();
            }
            await saveHistory(passphrase);
            updateHistoryUI();
            tempPassphrase = null; // Clear after use
        });
    });

    /**
     * Removes an item from the password history with undo option.
     * @param {number} index - The index of the item to remove.
     * @param {string} passphrase - The encryption passphrase.
     */
    const removeFromHistory = throttle(async (index, passphrase) => {
        if (index >= 0 && index < passwordHistory.length) {
            const deletedItem = passwordHistory.splice(index, 1)[0];
            deletedItems.push({ item: deletedItem, index });
            if (deletedItems.length > 5) deletedItems.shift(); // Limit undo history
            await saveHistory(passphrase);
            updateHistoryUI();
            showUndoOption(() => {
                passwordHistory.splice(index, 0, deletedItem);
                deletedItems.pop();
                saveHistory(passphrase).then(updateHistoryUI);
            });
        }
    });

    /**
     * Shows an undo option for deleted items.
     * @param {Function} undoCallback - The callback to restore the item.
     */
    function showUndoOption(undoCallback) {
        const undoDiv = document.createElement('div');
        undoDiv.classList.add('undo-message');
        undoDiv.innerHTML = 'Item deleted. <button class="undo-btn">Undo</button>';
        document.body.appendChild(undoDiv);
        const undoBtn = undoDiv.querySelector('.undo-btn');
        undoBtn.addEventListener('click', () => {
            undoCallback();
            undoDiv.remove();
        });
        setTimeout(() => undoDiv.remove(), 5000);
    }

    /**
     * Clears the entire password history.
     * @returns {Promise<boolean>} True if cleared, false if cancelled.
     */
    async function clearHistory() {
        return new Promise((resolve) => {
            showConfirmModal('Are you sure you want to clear your password history?', async (confirmed, passphrase) => {
                if (confirmed) {
                    tempPassphrase = passphrase;
                    passwordHistory.length = 0;
                    localStorage.removeItem(STORAGE_KEYS.HISTORY);
                    updateHistoryUI();
                    showError('History cleared successfully.', true);
                    tempPassphrase = null;
                    resolve(true);
                } else {
                    resolve(false);
                }
            });
        });
    }

    /**
     * Sets the encryption passphrase (validated only).
     * @param {string} passphrase - The passphrase to set.
     * @returns {Promise<boolean>} True if valid, false otherwise.
     */
    async function setEncryptionPassphrase(passphrase) {
        if (typeof passphrase !== 'string' || passphrase.trim() === '') {
            showError('Invalid passphrase.');
            return false;
        }
        if (typeof zxcvbn === 'function' && zxcvbn(passphrase).score < 3) {
            showError(ERROR_MESSAGES.WEAK_PASSPHRASE);
            return false;
        }
        return true;
    }

    /**
     * Resets the password history.
     */
    function resetPasswordHistory() {
        passwordHistory.length = 0;
        localStorage.removeItem(STORAGE_KEYS.HISTORY);
        updateHistoryUI();
    }

    /**
     * Displays an error or success message.
     * @param {string} message - The message to display.
     * @param {boolean} [isSuccess=false] - Whether the message is a success message.
     */
    function showError(message, isSuccess = false) {
        const errorDiv = document.createElement('div');
        errorDiv.classList.add(isSuccess ? 'success' : 'error');
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);
        setTimeout(() => errorDiv.remove(), 3000);
    }

    /**
     * Displays a confirmation modal.
     * @param {string} message - The message to display.
     * @param {function(boolean, string)} callback - Callback with confirmation status and passphrase.
     */
    function showConfirmModal(message, callback) {
        const modal = document.createElement('div');
        modal.classList.add('modal');
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'modal-title');
        modal.innerHTML = `
            <div class="modal-content">
                <h2 id="modal-title">${message}</h2>
                <p>${message}</p>
                <input type="password" id="modal-passphrase" placeholder="Enter passphrase" aria-label="Passphrase for confirmation">
                <div class="modal-actions">
                    <button type="button" class="confirm-btn w-full bg-blue-600 text-white">Confirm</button>
                    <button type="button" class="cancel-btn w-full bg-gray-300 text-black">Cancel</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        const mainContent = document.querySelector('main') || document.body;
        mainContent.setAttribute('inert', '');
        mainContent.setAttribute('aria-hidden', 'true');

        const confirmBtn = modal.querySelector('.confirm-btn');
        const cancelBtn = modal.querySelector('.cancel-btn');
        const passphraseInput = modal.querySelector('#modal-passphrase');
        const focusableElements = modal.querySelectorAll('button, input, [href], select, textarea, [tabindex]:not([tabindex="-1"])');
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        passphraseInput.focus();

        const handleKeydown = (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey && document.activeElement === firstElement) {
                    e.preventDefault();
                    lastElement.focus();
                } else if (!e.shiftKey && document.activeElement === lastElement) {
                    e.preventDefault();
                    firstElement.focus();
                }
            } else if (e.key === 'Escape') {
                modal.remove();
                mainContent.removeAttribute('inert');
                mainContent.removeAttribute('aria-hidden');
                callback(false, null);
            }
        };

        confirmBtn.addEventListener('click', () => {
            modal.remove();
            mainContent.removeAttribute('inert');
            mainContent.removeAttribute('aria-hidden');
            callback(true, passphraseInput.value);
        });
        cancelBtn.addEventListener('click', () => {
            modal.remove();
            mainContent.removeAttribute('inert');
            mainContent.removeAttribute('aria-hidden');
            callback(false, null);
        });
        modal.addEventListener('keydown', handleKeydown);
    }

    /**
     * Updates the history UI with search filtering.
     */
    function updateHistoryUI() {
        const historyList = document.getElementById('historyList');
        const searchInput = document.getElementById('history-search');
        if (!historyList) return;
        historyList.innerHTML = '';

        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const filteredHistory = passwordHistory.filter(item =>
            item.type.toLowerCase().includes(searchTerm) ||
            item.value.toLowerCase().includes(searchTerm)
        );

        if (filteredHistory.length === 0) {
            const emptyMessage = document.createElement('div');
            emptyMessage.textContent = searchTerm ? 'No matching history items.' : 'No history available.';
            historyList.appendChild(emptyMessage);
            return;
        }

        // Render only up to MAX_HISTORY items for performance (simplified virtualization)
        filteredHistory.slice(0, MAX_HISTORY).forEach((item, index) => {
            const historyItem = document.createElement('div');
            historyItem.classList.add('history-item');
            const typeBadge = document.createElement('span');
            typeBadge.classList.add('history-badge', `badge-${item.type}`);
            typeBadge.textContent = item.type;
            const valueDisplay = document.createElement('div');
            valueDisplay.classList.add('history-value');
            valueDisplay.textContent = '•'.repeat(item.value.length);
            valueDisplay.setAttribute('data-visible', 'false');
            const toggleBtn = document.createElement('button');
            toggleBtn.classList.add('history-toggle');
            toggleBtn.setAttribute('tabindex', '0');
            toggleBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
            toggleBtn.setAttribute('aria-label', `Show password for history item ${index + 1}`);
            toggleBtn.setAttribute('title', 'Toggle visibility');
            toggleBtn.addEventListener('click', () => toggleVisibility(valueDisplay, toggleBtn, item.value, index));
            toggleBtn.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleVisibility(valueDisplay, toggleBtn, item.value, index);
                }
            });
            const copyBtn = document.createElement('button');
            copyBtn.classList.add('history-action');
            copyBtn.setAttribute('tabindex', '0');
            copyBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
            copyBtn.setAttribute('aria-label', `Copy password for history item ${index + 1}`);
            copyBtn.setAttribute('title', 'Copy to clipboard');
            copyBtn.addEventListener('click', () => {
                showConfirmModal('Are you sure you want to copy this password?', async (confirmed, passphrase) => {
                    if (confirmed) {
                        try {
                            copyBtn.disabled = true;
                            await navigator.clipboard.writeText(item.value);
                            showError('Copied to clipboard!', true);
                            copyBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
                            setTimeout(() => {
                                copyBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
                                copyBtn.disabled = false;
                            }, 1500);
                        } catch {
                            showError('Failed to copy to clipboard');
                            copyBtn.disabled = false;
                        }
                    }
                });
            });
            copyBtn.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    copyBtn.click();
                }
            });
            const deleteBtn = document.createElement('button');
            deleteBtn.classList.add('history-action');
            deleteBtn.setAttribute('tabindex', '0');
            deleteBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>';
            deleteBtn.setAttribute('aria-label', `Delete history item ${index + 1}`);
            deleteBtn.setAttribute('title', 'Delete item');
            deleteBtn.addEventListener('click', () => {
                showConfirmModal('Are you sure you want to delete this history item?', async (confirmed, passphrase) => {
                    if (confirmed) {
                        tempPassphrase = passphrase;
                        await removeFromHistory(index, passphrase);
                        tempPassphrase = null;
                    }
                });
            });
            deleteBtn.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    deleteBtn.click();
                }
            });
            historyItem.append(typeBadge, valueDisplay, toggleBtn, copyBtn, deleteBtn);
            historyList.appendChild(historyItem);
        });
    }

    /**
     * Toggles visibility of a history item's value.
     * @param {HTMLElement} valueDisplay - The value display element.
     * @param {HTMLElement} toggleBtn - The toggle button.
     * @param {string} value - The actual value.
     * @param {number} index - The item index.
     */
    function toggleVisibility(valueDisplay, toggleBtn, value, index) {
        const isHidden = valueDisplay.getAttribute('data-visible') === 'false';
        valueDisplay.setAttribute('data-visible', isHidden ? 'true' : 'false');
        valueDisplay.textContent = isHidden ? value : '•'.repeat(value.length);
        toggleBtn.innerHTML = isHidden ?
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>' :
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        toggleBtn.setAttribute('aria-label', isHidden ? `Hide password for history item ${index + 1}` : `Show password for history item ${index + 1}`);
        toggleBtn.setAttribute('title', isHidden ? 'Hide visibility' : 'Show visibility');
    }

    /**
     * Initializes the password input toggle.
     */
    function initializePasswordInputToggle() {
        const passwordInput = document.getElementById('passphrase-input');
        if (!passwordInput) return;

        const toggleBtn = document.createElement('button');
        toggleBtn.classList.add('password-toggle');
        toggleBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        toggleBtn.setAttribute('aria-label', 'Show passphrase');
        toggleBtn.setAttribute('title', 'Toggle passphrase visibility');
        toggleBtn.style.position = 'absolute';
        toggleBtn.style.right = '10px';
        toggleBtn.style.top = '50%';
        toggleBtn.style.transform = 'translateY(-50%)';
        toggleBtn.style.background = 'none';
        toggleBtn.style.border = 'none';
        toggleBtn.style.cursor = 'pointer';

        const inputContainer = document.createElement('div');
        inputContainer.style.position = 'relative';
        inputContainer.style.display = 'inline-block';
        passwordInput.parentNode.insertBefore(inputContainer, passwordInput);
        inputContainer.appendChild(passwordInput);
        inputContainer.appendChild(toggleBtn);

        toggleBtn.addEventListener('click', () => {
            const isHidden = passwordInput.type === 'password';
            passwordInput.type = isHidden ? 'text' : 'password';
            toggleBtn.innerHTML = isHidden ?
                '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>' :
                '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
            toggleBtn.setAttribute('aria-label', isHidden ? 'Hide passphrase' : 'Show passphrase');
            toggleBtn.setAttribute('title', isHidden ? 'Hide passphrase visibility' : 'Show passphrase visibility');
        });
    }

    /**
     * Initializes the module.
     */
    function init() {
        initializePasswordInputToggle();
        updateHistoryUI();
        const searchInput = document.getElementById('history-search');
        if (searchInput) {
            searchInput.addEventListener('input', debounce(updateHistoryUI, 300));
        }
    }

    /**
     * Debounces a function to limit execution rate.
     * @param {Function} func - The function to debounce.
     * @param {number} wait - The debounce delay in milliseconds.
     * @returns {Function} The debounced function.
     */
    function debounce(func, wait) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    return {
        addToHistory,
        removeFromHistory,
        clearHistory,
        loadHistory,
        setEncryptionPassphrase,
        resetPasswordHistory,
        showError,
        init
    };
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PasswordHistoryManager;
} else if (typeof exports !== 'undefined') {
    exports.PasswordHistoryManager = PasswordHistoryManager;
} else {
    window.PasswordHistoryManager = PasswordHistoryManager;
}
