/**
 * Manages the passphrase modal UI for the Starpass Generator.
 * @module UIModule
 */

/**
 * Sanitizes input to prevent injection or invalid characters.
 * @param {string} value - The input value.
 * @returns {string} Sanitized value.
 */
function sanitizeInput(value) {
    return String(value).replace(/[^0-9a-zA-Z!@#$%^&*()-_=+[\]{}|;:,.<>?]/g, '');
}

/**
 * Logs errors to localStorage for debugging.
 * @param {Error} error - The error object.
 * @param {string} message - The error message.
 */
function logError(error, message) {
    try {
        const errorLog = JSON.parse(localStorage.getItem('errorLog') || '[]');
        errorLog.push({ timestamp: new Date().toISOString(), message, stack: error?.stack || 'No stack trace' });
        if (errorLog.length > 50) errorLog.shift();
        localStorage.setItem('errorLog', JSON.stringify(errorLog));
    } catch (e) {
        console.error('Failed to log error:', e);
    }
}

/**
 * Displays a modal for entering an encryption passphrase.
 * @param {function(string|null)} callback - Callback with the entered passphrase or null if cancelled.
 */
    function showPassphraseModal(callback) {
        if (typeof callback !== 'function') {
        logError(new TypeError('Invalid callback'), 'Callback must be a function');
        return;
     }

    // Cache DOM elements
    const modal = document.getElementById('passphrase-modal');
    const input = document.getElementById('passphrase-input');
    const remember = document.getElementById('remember-passphrase');
    const submitButton = document.getElementById('submit-passphrase');
    const clearButton = document.getElementById('clear-passphrase');
    const cancelButton = document.getElementById('cancel-passphrase');
    const errorDiv = document.createElement('div');

    if (!modal || !input || !remember || !submitButton || !clearButton || !cancelButton) {
        logError(new Error('Missing modal elements'), 'Modal elements not found');
        return;
    }

    // Initialize modal state
    input.value = '';
    remember.checked = false;
    errorDiv.className = 'error';
    errorDiv.style.display = 'none';
    errorDiv.setAttribute('aria-live', 'polite');
    modal.querySelector('.modal-content')?.prepend(errorDiv);

    // Show modal with fade-in
    modal.classList.add('show');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'modal-title');
    modal.setAttribute('aria-describedby', 'modal-description');

    // Make main content inert
    const mainContent = document.querySelector('main') || document.body;
    mainContent.setAttribute('inert', '');
    mainContent.setAttribute('aria-hidden', 'true');

    // Focus management
    const focusableElements = modal.querySelectorAll(
        'button, input:not([type="hidden"]), [href], select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    input.focus();

    /**
     * Displays an error message in the modal.
     * @param {string} message - The error message.
     */
    function showModalError(message) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
        errorDiv.style.opacity = '1';
        errorDiv.style.padding = 'var(--spacing-sm)';
        errorDiv.style.borderLeft = '4px solid var(--color-error)';
        setTimeout(() => {
            errorDiv.style.opacity = '0';
            errorDiv.style.padding = '0';
            errorDiv.style.borderLeft = 'none';
            errorDiv.style.display = 'none';
            errorDiv.textContent = '';
        }, 3000);
    }

    /**
     * Validates the passphrase input in real-time.
     */
    function validateInput() {
        const passphrase = sanitizeInput(input.value.trim());
        input.setAttribute('data-invalid', !passphrase);
        return !!passphrase;
    }

    // Event handlers
    function handleSubmit() {
        const passphrase = sanitizeInput(input.value.trim());
        if (!passphrase) {
            showModalError('Please enter a passphrase');
            input.focus();
            return;
        }
        modal.classList.remove('show');
        if (remember.checked) {
            try {
                sessionStorage.setItem('tempPassphrase', passphrase);
            } catch (e) {
                logError(e, 'Failed to save passphrase to sessionStorage');
            }
        }
        cleanup();
        callback(passphrase);
    }

    function handleClear() {
        input.value = '';
        input.setAttribute('data-invalid', 'true');
        input.focus();
    }

    function handleCancel() {
        modal.classList.remove('show');
        cleanup();
        callback(null);
    }

    function handleKeypress(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            handleSubmit();
        }
    }

    function handleKeydown(event) {
        if (event.key === 'Tab') {
            if (event.shiftKey && document.activeElement === firstElement) {
                event.preventDefault();
                lastElement.focus();
            } else if (!event.shiftKey && document.activeElement === lastElement) {
                event.preventDefault();
                firstElement.focus();
            }
        } else if (event.key === 'Escape') {
            event.preventDefault();
            handleCancel();
        }
    }

    function handleInput() {
        validateInput();
    }

    // Cleanup function
    function cleanup() {
        submitButton.removeEventListener('click', handleSubmit);
        clearButton.removeEventListener('click', handleClear);
        cancelButton.removeEventListener('click', handleCancel);
        input.removeEventListener('keypress', handleKeypress);
        input.removeEventListener('input', handleInput);
        modal.removeEventListener('keydown', handleKeydown);
        mainContent.removeAttribute('inert');
        mainContent.removeAttribute('aria-hidden');
        errorDiv.remove();
    }

    // Add event listeners
    submitButton.addEventListener('click', handleSubmit);
    clearButton.addEventListener('click', handleClear);
    cancelButton.addEventListener('click', handleCancel);
    input.addEventListener('keypress', handleKeypress);
    input.addEventListener('input', handleInput);
    modal.addEventListener('keydown', handleKeydown);

    // Initial validation
    validateInput();

    // Respect reduced motion preference
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        modal.style.transition = 'none';
    }
}