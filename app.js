/**
 * LRU Cache implementation for storing frequently accessed data
 * Used for caching password strength calculations
 */
class LRUCache {
  constructor(capacity) {
    this.capacity = capacity;
    this.cache = new Map();
    this.keyOrder = new Set(); // Tracks access order
  }

  /**
   * Retrieves the value associated with the given key.
   * If the key is not found, returns `null`.
   * @param {string} key
   * @returns {any|null}
   */
  get(key) {
    if (key == null) return null;
    if (!this.cache.has(key)) return null;

    const value = this.cache.get(key);
    this.keyOrder.delete(key); // Move to most recently used
    this.keyOrder.add(key);
    return value;
  }

  /**
   * Stores a key-value pair, evicting the least recently used item if needed.
   * @param {string} key
   * @param {any} value
   */
  set(key, value) {
    if (this.cache.has(key)) {
      this.keyOrder.delete(key);
    }

    this.cache.set(key, value);
    this.keyOrder.add(key);

    if (this.cache.size > this.capacity) {
      const oldestKey = this.keyOrder.values().next().value;
      this.keyOrder.delete(oldestKey);
      this.cache.delete(oldestKey);
    }
  }
}

/**
 * Main application module for the password generator
 */
const StarpassApp = (() => {
  // Private variables
  let wordList = [];
  let zxcvbnLoaded = false;
  let currentResult = {
    value: "",
    type: ""
  };

  // Initialize the strength cache with capacity of 10
  const strengthCache = new LRUCache(10);

  // Character sets used for password generation
  const CHARACTER_SETS = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    special: "!@#$%^&*()-_=+[]{}|;:,.<>?"
  };

  // Ambiguous characters to remove when that option is selected
  const AMBIGUOUS_CHARS = {
    lowercase: /[l]/g,
    uppercase: /[IO]/g,
    numbers: /[01]/g,
    special: /[(){}\[\]<>?]/g
  };
  // Translations for new UI elements (adding basic English translations)
  const translations = {
    en: {
      fillInStarryCryptBtn: "Fill in StarryCrypt",
      noPasswordError: "No password generated. Please generate a password first.",
      noCallbackError: "No callback URL provided.",
      callbackError: "Failed to redirect to StarryCrypt."
    }
  };
  /**
   * Securely logs errors without exposing sensitive data
   * @param {Error} error - The error object
   * @param {string} message - User-friendly error message
   * @param {boolean} isSuccess - Whether to display as success instead of error
   */
  function logError(error, message, isSuccess = false) {
    try {
      const errorLog = JSON.parse(localStorage.getItem("errorLog") || "[]");
      errorLog.push({
        timestamp: new Date().toISOString(),
        errorType: error?.name || "Unknown",
        message: message.replace(/[^a-zA-Z0-9\s\-_.]/g, ''), // Sanitize message
        userAgent: navigator.userAgent.substring(0, 50) // Truncated for privacy
      });

      if (errorLog.length > 25) {
        errorLog.splice(0, errorLog.length - 25);
      }

      if (getStorageQuota() > 0.9) {
        console.warn("localStorage quota nearly exceeded, clearing error log");
        localStorage.removeItem("errorLog");
      } else {
        localStorage.setItem("errorLog", JSON.stringify(errorLog));
      }
    } catch (e) {
      console.error("Failed to log error:", e.name);
    }

    displayMessage(
      {
        QuotaExceededError: "Storage limit exceeded. Please clear history or reduce entries.",
        TypeError: "Invalid input type. Please check curieux inputs.",
        SyntaxError: "Invalid data format. Please try again.",
        NetworkError: "Network error. Please check your connection.",
        SecurityError: "Security error. Please refresh the page."
      }[error?.name] || message,
      isSuccess
    );
  }


  /**
   * Estimates localStorage usage as a percentage of quota
   * @returns {number} Percentage of storage quota used
   */
  let cachedQuota = null;

  function getStorageQuota() {
    if (cachedQuota !== null) {
      return cachedQuota;
    }

    try {
      if (typeof localStorage === "undefined" || localStorage === null) {
        console.warn("localStorage is unavailable. Returning 0 for storage quota.");
        return 0;
      }

      const used = Object.keys(localStorage).reduce((total, key) => {
        const value = localStorage.getItem(key);
        return total + key.length + (value ? value.length : 0);
      }, 0);
      const total = 5 * 1024 * 1024; // Estimate 5MB limit
      cachedQuota = used / total;
      return cachedQuota;
    } catch (error) {
      console.warn("Error accessing localStorage:", error.message);
      return 0;
    }
  }

  window.addEventListener("storage", () => {
    cachedQuota = null;
  });

  /**
   * Robust input sanitization with proper null/undefined handling
   * @param {any} input - The input to sanitize
   * @returns {string} Sanitized string
   */
  function sanitizeInput(input) {
    if (input == null || input === undefined) {
      return "";
    }

    if (typeof input === 'number') {
      return String(input);
    }

    if (typeof input !== 'string') {
      input = String(input);
    }

    return input
      .trim()
      .replace(/[<>\"'&]/g, '') // Remove HTML/script injection chars
      .replace(/[^\x20-\x7E]/g, ''); // Remove non-printable chars
  }

  /**
   * Validates numeric input fields with enhanced error reporting and total length check
   * @param {HTMLElement} element - The input element
   * @param {number} min - Minimum allowed value
   * @param {number} max - Maximum allowed value
   * @returns {boolean} Whether the input is valid
   */
  function validateNumericInput(element, min, max) {
    if (!element) {
      console.warn("validateNumericInput: element is null");
      return false;
    }

    const value = parseInt(sanitizeInput(element.value)) || 0;
    const isRangeValid = !isNaN(value) && value >= min && value <= max;
    let isTotalValid = true;

    if (['lowercase', 'uppercase', 'numbers', 'special'].includes(element.id)) {
      isTotalValid = validateTotalLength();
    } else if (element.id === 'password-length') {
      isTotalValid = validateTotalLength();
    }

    const isValid = isRangeValid && isTotalValid;
    element.setAttribute("data-invalid", !isValid);
    element.setAttribute("aria-invalid", !isValid);

    if (!isValid) {
      element.setAttribute("aria-describedby",
        element.getAttribute("aria-describedby") + " validation-error");
    } else {
      element.removeAttribute("aria-describedby");
    }

    return isValid;
  }

  /**
   * Validates that the sum of character counts doesn't exceed password length
   * @returns {boolean} Whether the total length is valid
   */
  function validateTotalLength() {
    const elements = {
      lowercase: getElementById("lowercase"),
      uppercase: getElementById("uppercase"),
      numbers: getElementById("numbers"),
      special: getElementById("special"),
      length: getElementById("password-length")
    };

    const settings = {
      lowercase: parseInt(sanitizeInput(elements.lowercase?.value)) || 0,
      uppercase: parseInt(sanitizeInput(elements.uppercase?.value)) || 0,
      numbers: parseInt(sanitizeInput(elements.numbers?.value)) || 0,
      special: parseInt(sanitizeInput(elements.special?.value)) || 0,
      length: parseInt(sanitizeInput(elements.length?.value)) || 16
    };

    const totalSpecified = settings.lowercase + settings.uppercase + settings.numbers + settings.special;
    return totalSpecified <= settings.length;
  }

  /**
   * Toggles dark mode with proper string conversion
   */
  function toggleDarkMode() {
    const isDarkMode = localStorage.getItem("darkMode") !== "true";
    localStorage.setItem("darkMode", isDarkMode.toString());
    document.body.classList.toggle("dark-mode", isDarkMode);
  }

  /**
   * Toggles high contrast mode with proper string conversion
   */
  function toggleHighContrast() {
    const isHighContrast = localStorage.getItem("highContrast") !== "true";
    localStorage.setItem("highContrast", isHighContrast.toString());
    document.body.classList.toggle("high-contrast", isHighContrast);
  }

  /**
   * Generates a cryptographically secure random number within range
   * Falls back to Math.random if crypto is unavailable.
   * @param {number} max - Maximum value (exclusive)
   * @returns {number} Random number between 0 and max - 1
   */
  function getSecureRandom(max) {
    if (max <= 0) return 0;

    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      const threshold = Math.floor(0xFFFFFFFF / max) * max;
      let randomValue;
      do {
        const randomBuffer = new Uint32Array(1);
        crypto.getRandomValues(randomBuffer);
        randomValue = randomBuffer[0];
      } while (randomValue >= threshold);
      return randomValue % max;
    } else {
      console.warn("crypto.getRandomValues is not available. Falling back to Math.random.");
      return Math.floor(Math.random() * max);
    }
  }

  /**
   * Loads the common words list with quota checking
   * @returns {Promise<boolean>} Whether words were successfully loaded
   */
  async function loadWordList() {
    if (wordList.length > 0) {
      return true;
    }

    if (getStorageQuota() > 0.8) {
      console.warn("localStorage quota high, skipping word list cache");
      return await fetchWordListFromServer();
    }

    const cachedWords = localStorage.getItem("commonWords");
    const cachedVersion = localStorage.getItem("commonWordsVersion");

    if (cachedWords && cachedVersion === "1.0") {
      try {
        wordList = JSON.parse(cachedWords);
        return true;
      } catch (error) {
        logError(error, "Failed to parse cached words.");
        localStorage.removeItem("commonWords");
      }
    }

    return await fetchWordListFromServer();
  }

  /**
   * Fetches word list from server with improved error handling
   * @returns {Promise<boolean>} Success status
   */
  async function fetchWordListFromServer() {
    try {
      const response = await fetch("src/common_wordslist.json");
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      wordList = await response.json();
      if (getStorageQuota() < 0.7) {
        try {
          localStorage.setItem("commonWords", JSON.stringify(wordList));
          localStorage.setItem("commonWordsVersion", "1.0");
        } catch (quotaError) {
          if (quotaError.name === "QuotaExceededError") {
            console.warn("Cannot cache word list due to storage quota being exceeded during caching.");
            localStorage.removeItem("commonWords");
            localStorage.removeItem("commonWordsVersion");
          } else {
            throw quotaError;
          }
        }
      }
      return true;
    } catch (error) {
      logError(error, "Failed to load word list. Please try again.");
      displayMessage("Network error: Using fallback word list.", false);
      wordList = [
        "apple", "banana", "cherry", "dragon", "elephant", "forest", "guitar",
        "house", "island", "jungle", "kitten", "lemon", "mountain", "ocean",
        "piano", "quiet", "river", "sunset", "tiger", "umbrella", "violet",
        "window", "yellow", "zebra"
      ];
      return true;
    }
  }

  /**
   * Gets an element by ID with comprehensive error handling
   * @param {string} id - Element ID
   * @returns {HTMLElement|null} The element or null if not found
   */
  function getElementById(id) {
    if (!id || typeof id !== 'string') {
        console.error("getElementById: Invalid ID provided");
        return null;
    }

    const element = document.getElementById(id);
    if (!element && id !== "error") { // Skip message for "error" to avoid recursion
        console.warn(`Element with ID "${id}" not found`);
        if (document.body) {
            const tempMessage = document.createElement('div');
            tempMessage.textContent = `Missing interface element: ${id}. Please refresh the page.`;
            tempMessage.style.cssText = `
                position: fixed; top: 20px; right: 20px;
                padding: 10px; border-radius: 4px; z-index: 9999;
                background: #f8d7da; color: #721c24;
                border: 1px solid #f5c6cb;
            `;
            document.body.appendChild(tempMessage);
          setTimeout(function removeTempMessage() { // Named function
              tempMessage.remove();
          }, 3000);
      }
  }
  return element;
}
/**
 * Displays a message to the user with enhanced accessibility
 * @param {string} message - The message to display
 * @param {boolean} isSuccess - Whether this is a success message
 */
function displayMessage(message, isSuccess = false) {
    // Use direct DOM access to avoid recursion
    let errorElement = document.getElementById("error");
    if (!errorElement) {
        console.warn("Error element not found, using fallback");
        if (!document.body) {
            console.error("document.body not available");
            return;
        }
        errorElement = document.createElement('div');
        errorElement.id = "temp-error";
        errorElement.style.cssText = `
            position: fixed; top: 20px; right: 20px;
            padding: 10px; border-radius: 4px; z-index: 9999;
            background: ${isSuccess ? '#d4edda' : '#f8d7da'};
            color: ${isSuccess ? '#155724' : '#721c24'};
            border: 1px solid ${isSuccess ? '#c3e6cb' : '#f5c6cb'};
        `;
        document.body.appendChild(errorElement);
    }

    errorElement.textContent = message;
    errorElement.style.opacity = "1";
    errorElement.style.padding = "8px";
    errorElement.style.borderLeft = `4px solid ${isSuccess ? '#28a745' : '#dc3545'}`;
    errorElement.classList.toggle("success", isSuccess);
    errorElement.setAttribute("role", "alert");

    setTimeout(function clearMessage() { // Named function to avoid unnamed statement
        errorElement.textContent = "";
        errorElement.style.opacity = "0";
        errorElement.style.padding = "0";
        errorElement.style.borderLeft = "none";
        errorElement.classList.remove("success");
        errorElement.removeAttribute("role");
        if (errorElement.id === "temp-error") {
            errorElement.remove();
        }
    }, 3000);
}

  /**
   * Validates that a number is within range
   * @param {number} value - The value to check
   * @param {number} min - Minimum allowed value
   * @param {number} max - Maximum allowed value
   * @returns {boolean} Whether the value is valid
   */
  function isValidNumber(value, min, max = Infinity) {
    return value != null && !isNaN(value) && value >= min && value <= max;
  }

  /**
   * Generates random characters from a given set
   * @param {string} charSet - Set of characters to choose from
   * @param {number} count - Number of characters to generate
   * @returns {string} Random characters
   */
  function generateRandomChars(charSet, count) {
    if (!charSet || count <= 0) return "";
    if (charSet.length === 0) return "";

    const result = [];
    for (let i = 0; i < count; i++) {
      const randomIndex = getSecureRandom(charSet.length);
      result.push(charSet.charAt(randomIndex));
    }

    return result.join("");
  }

  /**
   * Sets the result in the UI
   * @param {string} result - The generated password/passphrase/username
   */
  function setResult(result) {
    const resultElement = getElementById("result");
    const outputElement = getElementById("output");
    const strengthBarElement = getElementById("strength-bar");
    const crackTimeElement = getElementById("crack-time");

    if (resultElement && outputElement) {
      resultElement.textContent = result;
      resultElement.setAttribute("aria-live", "polite");
      outputElement.classList.remove("hidden");

      const isUsername = currentResult.type === "username";
      if (strengthBarElement) {
        strengthBarElement.style.display = isUsername ? "none" : "block";
      }
      if (crackTimeElement) {
        crackTimeElement.style.display = isUsername ? "none" : "block";
        if (isUsername) {
          crackTimeElement.textContent = "";
        }
      }

      setTimeout(() => {
        resultElement.setAttribute("aria-live", "off");
      }, 100);
    }
  }

  /**
   * Modern clipboard API with secure fallback
   * @param {string} text - Text to copy
   * @returns {Promise<boolean>} Success status
   */
  async function copyToClipboard(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }

      if (window.getSelection) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
        textArea.setAttribute('readonly', '');
        textArea.setAttribute('tabindex', '-1');

        document.body.appendChild(textArea);
        textArea.select();
        textArea.setSelectionRange(0, text.length);

        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);

        if (!successful) {
          throw new Error('execCommand failed');
        }

        return true;
      }

      throw new Error('No clipboard API available');
    } catch (error) {
      console.error('Copy failed:', error);
      return false;
    }
  }

  /**
   * Saves current result to history
   * @returns {Promise<void>}
   */
  async function saveToHistory() {
    if (!currentResult.value) {
      displayMessage("No result to save");
      return;
    }

    try {
      if (typeof window.HistoryManager !== 'undefined') {
        await window.HistoryManager.addEntry({
          value: currentResult.value,
          type: currentResult.type,
          timestamp: new Date().toISOString(),
          strength: strengthCache.get(currentResult.value)?.label || 'Unknown'
        });
        displayMessage("Saved to history!", true);
      } else {
        const history = JSON.parse(localStorage.getItem('starpass_history') || '[]');
        history.unshift({
          value: currentResult.value,
          type: currentResult.type,
          timestamp: new Date().toISOString()
        });

        if (history.length > 50) {
          history.splice(50);
        }

        localStorage.setItem('starpass_history', JSON.stringify(history));
        displayMessage("Saved to history!", true);
      }
    } catch (error) {
      logError(error, "Failed to save to history");
    }
  }

  /**
   * Calculates password strength with enhanced granularity
   * @param {string} password - The password to analyze
   */
  async function calculateStrength(password) {
    const strengthBarElement = getElementById("strength-bar-fill");
    const crackTimeElement = getElementById("crack-time");

    if (!strengthBarElement || !crackTimeElement) {
      console.warn("Strength display elements not found");
      return;
    }

    // Check cache first
    const cachedStrength = strengthCache.get(password);
    if (cachedStrength) {
      displayStrength(cachedStrength);
      return;
    }

    // Clear existing strength classes
    strengthBarElement.classList.remove(
      "strength-very-weak",
      "strength-weak",
      "strength-medium",
      "strength-strong",
      "strength-very-strong"
    );

    if (!zxcvbnLoaded) {
      try {
        await loadZxcvbn();
      } catch (error) {
        console.warn("zxcvbn failed to load, using basic strength calculation:", error.message);
        calculateBasicStrength(password);
        return;
      }
    }

    try {
      const result = zxcvbn(password);
      const score = result.score; // 0-4 scale
      const entropy = result.guesses_log10; // Log10 of guesses
      const crackTimeSeconds = result.crack_times_seconds.offline_fast_hashing_1e10_per_second;

      // Normalize score to 0-100 based on entropy and crack time
      const normalizedScore = Math.min(100, Math.max(0, Math.round(
        (score / 4) * 50 + // Base score contributes 50%
        (Math.min(entropy, 20) / 20) * 30 + // Entropy contributes 30%
        (Math.log10(Math.max(crackTimeSeconds, 1)) / 12) * 20 // Crack time contributes 20%
      )));

      const crackTimeText = formatCrackTime(crackTimeSeconds);
      const label = normalizedScore < 20 ? "Very Weak" :
        normalizedScore < 40 ? "Weak" :
          normalizedScore < 60 ? "Medium" :
            normalizedScore < 80 ? "Strong" : "Very Strong";

      const strengthInfo = {
        score: normalizedScore,
        label: label,
        crackTimeText: crackTimeText,
        entropy: entropy.toFixed(2),
        suggestions: result.feedback.suggestions
      };

      strengthCache.set(password, strengthInfo);
      displayStrength(strengthInfo);
    } catch (error) {
      logError(error, "Failed to calculate strength.");
      calculateBasicStrength(password);
    }
  }

  /**
   * Loads zxcvbn library with timeout
   * @returns {Promise<void>}
   */
  function loadZxcvbn() {
    return new Promise((resolve, reject) => {
      if (typeof zxcvbn === "function") {
        zxcvbnLoaded = true;
        console.log("zxcvbn already loaded");
        return resolve();
      }

      const loadScript = (src, timeout = 5000) => {
        return new Promise((resolveScript, rejectScript) => {
          const script = document.createElement("script");
          script.src = src;
          script.async = true;

          const timer = setTimeout(() => {
            script.remove();
            rejectScript(new Error(`zxcvbn load timeout for ${src}`));
          }, timeout);

          script.onload = () => {
            clearTimeout(timer);
            if (typeof zxcvbn === "function") {
              resolveScript();
            } else {
              rejectScript(new Error(`zxcvbn not defined after loading ${src}`));
            }
          };

          script.onerror = () => {
            clearTimeout(timer);
            script.remove();
            rejectScript(new Error(`Failed to load zxcvbn from ${src}`));
          };

          document.head.appendChild(script);
        });
      };

      loadScript("src/zxcvbn.min.js")
        .then(() => {
          zxcvbnLoaded = true;
          console.log("zxcvbn loaded from local src/zxcvbn.min.js");
          resolve();
        })
        .catch((localError) => {
          console.warn("Local zxcvbn load failed:", localError.message);
          loadScript("https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.min.js")
            .then(() => {
              zxcvbnLoaded = true;
              console.log("zxcvbn loaded from jsDelivr CDN");
              resolve();
            })
            .catch((cdnError) => {
              console.warn("jsDelivr zxcvbn load failed:", cdnError.message);
              reject(new Error("Failed to load zxcvbn from both local and jsDelivr"));
            });
        });
    });
  }

  /**
   * Formats a crack time in seconds to a human-readable string
   * @param {number} seconds - Crack time in seconds
   * @returns {string} Formatted time string
   */
  function formatCrackTime(seconds) {
    if (seconds < 60) {
      return `${Math.round(seconds)} seconds`;
    } else if (seconds < 3600) {
      return `${Math.round(seconds / 60)} minutes`;
    } else if (seconds < 86400) {
      return `${Math.round(seconds / 3600)} hours`;
    } else if (seconds < 31536000) {
      return `${Math.round(seconds / 86400)} days`;
    } else {
      return `${Math.round(seconds / 31536000)} years`;
    }
  }

  /**
   * Displays password strength in the UI with dynamic gradient
   * @param {Object} strengthInfo - Strength information
   */
  function displayStrength({ score, label, crackTimeText, entropy, suggestions }) {
    const strengthBarElement = getElementById("strength-bar-fill");
    const crackTimeElement = getElementById("crack-time");

    if (strengthBarElement && crackTimeElement) {
      // Apply gradient based on score
      const hue = Math.min(120, score * 1.2); // Red (0) to Green (120)
      strengthBarElement.style.background = `hsl(${hue}, 70%, 50%)`;
      strengthBarElement.style.width = `${score}%`;
      strengthBarElement.setAttribute("aria-valuenow", score);
      strengthBarElement.setAttribute("aria-valuetext", `${label} (Score: ${score}/100)`);
      crackTimeElement.textContent = `Strength: ${label} (Crack time: ${crackTimeText}, Entropy: ${entropy} bits)`;

      // Add tooltip with detailed info
      strengthBarElement.setAttribute("title",
        `Strength: ${label}\nScore: ${score}/100\nCrack time: ${crackTimeText}\nEntropy: ${entropy} bits\nSuggestions: ${suggestions.join(" ") || "None"}`);
    }
  }

  /**
   * Calculates basic password strength when zxcvbn is unavailable
   * @param {string} password - The password to analyze
   */
  function calculateBasicStrength(password) {
    const length = password.length;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    let score = 0;
    if (length >= 12) score += 20;
    if (length >= 16) score += 20;
    if (hasLower && hasUpper) score += 20;
    if (hasNumber) score += 20;
    if (hasSpecial) score += 20;

    const label = score < 20 ? "Very Weak" :
      score < 40 ? "Weak" :
        score < 60 ? "Medium" :
          score < 80 ? "Strong" : "Very Strong";

    const strengthInfo = {
      score: score,
      label: label,
      crackTimeText: "Estimation unavailable",
      entropy: "Unknown",
      suggestions: []
    };

    strengthCache.set(password, strengthInfo);
    displayStrength(strengthInfo);
  }

  /**
   * Shuffles a string randomly
   * @param {string} str - String to shuffle
   * @returns {string} Shuffled string
   */
  function shuffleString(str) {
    const chars = str.split("");
    for (let i = chars.length - 1; i > 0; i--) {
      const j = getSecureRandom(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  /**
   * Sets up input validation and real-time strength preview
   */
  function setupInputValidation() {
    const fields = [
      { id: "password-length", min: 1, max: 1000 },
      { id: "lowercase", min: 0, max: 1000 },
      { id: "uppercase", min: 0, max: 1000 },
      { id: "numbers", min: 0, max: 1000 },
      { id: "special", min: 0, max: 1000 },
      { id: "word-count", min: 1, max: 100 },
      { id: "username-length", min: 1, max: 100 },
      { id: "username-word-count", min: 1, max: 50 }
    ];

    fields.forEach(({ id, min, max }) => {
      const element = getElementById(id);
      if (element) {
        element.addEventListener(
          "input",
          debounce(() => {
            validateNumericInput(element, min, max);
            if (['password-length', 'lowercase', 'uppercase', 'numbers', 'special', 'word-count'].includes(id)) {
              previewStrength();
            }
          }, 300)
        );
        validateNumericInput(element, min, max);
      }
    });

    // Add real-time preview for checkboxes
    ['exclude-ambiguous', 'capitalize-words', 'include-number', 'include-special'].forEach(id => {
      const element = getElementById(id);
      if (element) {
        element.addEventListener("change", debounce(previewStrength, 300));
      }
    });

    /**
     * Creates a debounced function
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function} Debounced function
     */
    function debounce(func, wait) {
      let timeout;
      return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      };
    }
  }

  /**
   * Previews strength based on current settings
   */
  async function previewStrength() {
    const activeTab = document.querySelector('.tab-content.active').id;
    let previewText = "";

    if (activeTab === "password") {
      const elements = {
        lowercase: getElementById("lowercase"),
        uppercase: getElementById("uppercase"),
        numbers: getElementById("numbers"),
        special: getElementById("special"),
        length: getElementById("password-length"),
        excludeAmbiguous: getElementById("exclude-ambiguous")
      };

      const settings = {
        lowercase: parseInt(sanitizeInput(elements.lowercase?.value)) || 0,
        uppercase: parseInt(sanitizeInput(elements.uppercase?.value)) || 0,
        numbers: parseInt(sanitizeInput(elements.numbers?.value)) || 0,
        special: parseInt(sanitizeInput(elements.special?.value)) || 0,
        length: parseInt(sanitizeInput(elements.length?.value)) || 16,
        excludeAmbiguous: elements.excludeAmbiguous?.checked || false
      };

      if (settings.lowercase + settings.uppercase + settings.numbers + settings.special === 0) {
        displayStrength({ score: 0, label: "Very Weak", crackTimeText: "0 seconds", entropy: "0", suggestions: [] });
        return;
      }

      let charSets = { ...CHARACTER_SETS };
      if (settings.excludeAmbiguous) {
        charSets.lowercase = charSets.lowercase.replace(/[l]/g, "");
        charSets.uppercase = charSets.uppercase.replace(/[IO]/g, "");
        charSets.numbers = charSets.numbers.replace(/[01]/g, "");
        charSets.special = charSets.special.replace(/[(){}\[\]]/g, "");
      }

      previewText += generateRandomChars(charSets.lowercase, settings.lowercase);
      previewText += generateRandomChars(charSets.uppercase, settings.uppercase);
      previewText += generateRandomChars(charSets.numbers, settings.numbers);
      previewText += generateRandomChars(charSets.special, settings.special);

      if (previewText.length < settings.length) {
        let remainingChars = "";
        if (settings.lowercase > 0) remainingChars += charSets.lowercase;
        if (settings.uppercase > 0) remainingChars += charSets.uppercase;
        if (settings.numbers > 0) remainingChars += charSets.numbers;
        if (settings.special > 0) remainingChars += charSets.special;
        previewText += generateRandomChars(remainingChars, settings.length - previewText.length);
      }

      previewText = shuffleString(previewText);
    } else if (activeTab === "passphrase") {
      if (!await loadWordList()) return;

      const elements = {
        wordCount: getElementById("word-count"),
        separator: getElementById("separator"),
        capitalizeWords: getElementById("capitalize-words"),
        includeNumber: getElementById("include-number"),
        includeSpecial: getElementById("include-special")
      };

      const wordCount = parseInt(sanitizeInput(elements.wordCount?.value)) || 4;
      const separatorMap = {
        'hyphen': '-',
        'dot': '.',
        'underscore': '_',
        'space': ' ',
        'none': ''
      };
      const separator = separatorMap[elements.separator?.value] || '-';
      const capitalizeWords = elements.capitalizeWords?.checked || false;
      const includeNumber = elements.includeNumber?.checked || false;
      const includeSpecial = elements.includeSpecial?.checked || false;

      let words = [];
      for (let i = 0; i < wordCount; i++) {
        const randomIndex = getSecureRandom(wordList.length);
        let word = wordList[randomIndex];
        if (capitalizeWords) {
          word = word.charAt(0).toUpperCase() + word.slice(1);
        }
        words.push(word);
      }

      previewText = words.join(separator);
      if (includeNumber) {
        previewText += getSecureRandom(1000);
      }
      if (includeSpecial) {
        const specialChars = "!@#$%^&*()-_=+";
        const randomIndex = getSecureRandom(specialChars.length);
        previewText += specialChars.charAt(randomIndex);
      }
    }

    if (previewText) {
      calculateStrength(previewText);
    }
  }

  return {
    init: function () {
      this.setupDefaults();
      this.setupThemeToggles();
      this.setupFormSubmissions();
      this.setupTabSwitching();
      this.setupCopyAndSaveButtons();
      this.setupRangeInputDisplays();
      this.setupFillInStarryCrypt();
    },

    setupDefaults: function () {
      setupInputValidation();

      const defaults = {
        "password-length": "16",
        "lowercase": "4",
        "uppercase": "4",
        "numbers": "4",
        "special": "4",
        "word-count": "4",
        "username-length": "10",
        "username-word-count": "3"
      };

      Object.entries(defaults).forEach(([id, value]) => {
        const input = getElementById(id);
        if (input && !input.value) {
          input.value = value;
          const span = document.querySelector(`label[for="${id}"] span`);
          if (span) {
            span.textContent = value;
          }
        }
      });

      const checkboxDefaults = {
        "exclude-ambiguous": false,
        "capitalize-words": false,
        "include-number": false,
        "include-special": false,
        "include-number-username": false,
        "all-lowercase": true
      };

      Object.entries(checkboxDefaults).forEach(([id, checked]) => {
        const input = getElementById(id);
        if (input && input.type === "checkbox") {
          input.checked = checked;
        }
      });
    },

    setupThemeToggles: function () {
      const darkModeToggle = getElementById("dark-mode-toggle");
      const highContrastToggle = getElementById("high-contrast-toggle");

      if (darkModeToggle) {
        darkModeToggle.addEventListener("click", toggleDarkMode);
      }

      if (highContrastToggle) {
        highContrastToggle.addEventListener("click", toggleHighContrast);
      }

      if (localStorage.getItem("darkMode") === "true") {
        document.body.classList.add("dark-mode");
      }

      if (localStorage.getItem("highContrast") === "true") {
        document.body.classList.add("high-contrast");
      }
    },

    setupFormSubmissions: function () {
      const forms = [
        { selector: '#password-form', handler: () => this.generatePassword() },
        { selector: '#passphrase-form', handler: () => this.generatePassphrase() },
        { selector: '#username-form', handler: () => this.generateUsername() }
      ];

      forms.forEach(({ selector, handler }) => {
        const form = document.querySelector(selector);
        if (form) {
          form.addEventListener("submit", (event) => {
            event.preventDefault();
            handler();
          });
        }
      });
    },

    setupTabSwitching: function () {
      document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', () => {
          const tabName = button.getAttribute('data-tab');
          this.switchTab(tabName);
        });
      });
    },

    setupCopyAndSaveButtons: function () {
      const copyButton = Array.from(document.querySelectorAll('button'))
        .find(btn => btn.textContent.includes('Copy'));
      const saveButton = Array.from(document.querySelectorAll('button'))
        .find(btn => btn.textContent.includes('Save'));

      if (copyButton) {
        copyButton.addEventListener('click', async () => {
          if (currentResult.value) {
            const success = await copyToClipboard(currentResult.value);
            if (success) {
              displayMessage('Copied to clipboard!', true);
              copyButton.textContent = 'Copied!';
              setTimeout(() => {
                copyButton.textContent = 'Copy to Clipboard';
              }, 2000);
            } else {
              displayMessage('Copy failed. Please select and copy manually.');
            }
          } else {
            displayMessage('Nothing to copy');
          }
        });
      }

      if (saveButton) {
        saveButton.addEventListener('click', saveToHistory);
      }
    },

    setupRangeInputDisplays: function () {
      ['password-length', 'word-count', 'username-length', 'username-word-count'].forEach(id => {
        const input = getElementById(id);
        const span = document.querySelector(`label[for="${id}"] span`);

        if (input && span) {
          input.addEventListener('input', () => {
            span.textContent = input.value;
          });
        }
      });
    },
    setupFillInStarryCrypt: function () {
      const fillInStarryCryptBtn = document.getElementById("fill-in-starrycrypt");
      if (fillInStarryCryptBtn) {
          // Remove any existing listeners to prevent duplication
          fillInStarryCryptBtn.replaceWith(fillInStarryCryptBtn.cloneNode(true));
          const newBtn = document.getElementById("fill-in-starrycrypt");

          // Check if callback URL is present
          const urlParams = new URLSearchParams(window.location.search);
          const callbackUrl = urlParams.get("callback");
          if (!callbackUrl) {
              newBtn.style.display = "none"; // Hide button
          } else {
              newBtn.style.display = "block";
              newBtn.textContent = translations.en.fillInStarryCryptBtn;
              newBtn.addEventListener("click", () => this.fillInStarryCrypt(), { once: true });
          }
      }
  },

  fillInStarryCrypt: function () {
      const currentResult = this.getCurrentResult();
      if (!currentResult.value) {
          this.displayMessage(translations.en.noPasswordError, false);
          return;
      }

      const urlParams = new URLSearchParams(window.location.search);
      let callbackUrl = urlParams.get("callback");

      if (!callbackUrl) {
          this.displayMessage(translations.en.noCallbackError, false);
          return;
      }

      try {
          // Sanitize the password
          const sanitizedPassword = this.sanitizeInput(currentResult.value);
          if (!sanitizedPassword) {
              this.displayMessage(translations.en.noPasswordError, false);
              return;
          }

          // Decode and validate callback URL
          callbackUrl = decodeURIComponent(callbackUrl);

          // Validate URL to prevent loops
          const parsedUrl = new URL(callbackUrl, window.location.origin);
          if (parsedUrl.origin === window.location.origin) {
              console.warn("Callback URL points to Starpass, preventing redirect loop");
              this.displayMessage(translations.en.callbackError, false);
              return;
          }

          if (!callbackUrl.includes("starpass_password={password}")) {
              console.warn("Invalid callback URL format");
              this.displayMessage(translations.en.callbackError, false);
              return;
          }

          // Replace {password} placeholder
          const encodedPassword = encodeURIComponent(sanitizedPassword);
          const finalUrl = callbackUrl.replace("{password}", encodedPassword);

          // Redirect
          window.location.href = finalUrl;
      } catch (error) {
          console.error("Failed to process callback URL:", error);
          this.displayMessage(translations.en.callbackError, false);
      }
}
,
switchTab: function (tabName) {
      document.querySelectorAll(".tab-content").forEach(tab =>
        tab.classList.remove("active")
      );

      document.querySelectorAll(".tab-button").forEach(button =>
        button.classList.remove("active")
      );

      const selectedButton = document.querySelector(`[data-tab="${tabName}"]`);
      const selectedTab = getElementById(tabName);
      const outputElement = getElementById("output");
      const strengthBarElement = getElementById("strength-bar");
      const crackTimeElement = getElementById("crack-time");

      if (selectedButton) {
        selectedButton.classList.add("active");
        selectedButton.setAttribute("aria-selected", "true");
      }

      if (selectedTab) {
        selectedTab.classList.add("active");
      }

      if (outputElement) {
        outputElement.classList.toggle("hidden", !currentResult.value);
      }

      if (strengthBarElement) {
        strengthBarElement.style.display = tabName === "username" ? "none" : "block";
      }
      if (crackTimeElement) {
        crackTimeElement.style.display = tabName === "username" ? "none" : "block";
        if (tabName === "username") {
          crackTimeElement.textContent = "";
        }
      }

      // Trigger strength preview on tab switch
      previewStrength();
    },

    generatePassword: function () {
      const errorElement = getElementById("error");
      if (errorElement) {
        errorElement.style.opacity = "0";
        errorElement.style.padding = "0";
        errorElement.style.borderLeft = "none";
      }

      const elementIds = ["lowercase", "uppercase", "numbers", "special", "password-length", "exclude-ambiguous"];
      const elements = {};
      let missingElements = [];

      elementIds.forEach(id => {
        elements[id] = getElementById(id);
        if (!elements[id]) {
          missingElements.push(id);
        }
      });

      if (missingElements.length > 0) {
        displayMessage(`Missing interface elements: ${missingElements.join(", ")}. Please refresh the page.`);
        return;
      }

      const settings = {
        lowercase: parseInt(sanitizeInput(elements.lowercase.value)) || 0,
        uppercase: parseInt(sanitizeInput(elements.uppercase.value)) || 0,
        numbers: parseInt(sanitizeInput(elements.numbers.value)) || 0,
        special: parseInt(sanitizeInput(elements.special.value)) || 0,
        length: parseInt(sanitizeInput(elements['password-length'].value)) || 16
      };

      const excludeAmbiguous = elements['exclude-ambiguous'].checked;

      if (!Object.values(settings).every(val => isValidNumber(val, 0, 1000)) ||
        !isValidNumber(settings.length, 1, 1000)) {
        displayMessage("Please enter valid numbers (1-1000 for length, 0-1000 for counts).");
        return;
      }

      const totalSpecified = settings.lowercase + settings.uppercase + settings.numbers + settings.special;
      if (totalSpecified > settings.length) {
        displayMessage("Sum of character counts exceeds password length.");
        return;
      }

      if (totalSpecified === 0) {
        displayMessage("Please select at least one character type.");
        return;
      }

      let charSets = { ...CHARACTER_SETS };
      if (excludeAmbiguous) {
        charSets.lowercase = charSets.lowercase.replace(/[l]/g, "");
        charSets.uppercase = charSets.uppercase.replace(/[IO]/g, "");
        charSets.numbers = charSets.numbers.replace(/[01]/g, "");
        charSets.special = charSets.special.replace(/[(){}\[\]]/g, "");
      }

      let password = "";
      password += generateRandomChars(charSets.lowercase, settings.lowercase);
      password += generateRandomChars(charSets.uppercase, settings.uppercase);
      password += generateRandomChars(charSets.numbers, settings.numbers);
      password += generateRandomChars(charSets.special, settings.special);

      if (password.length < settings.length) {
        let remainingChars = "";
        if (settings.lowercase > 0) remainingChars += charSets.lowercase;
        if (settings.uppercase > 0) remainingChars += charSets.uppercase;
        if (settings.numbers > 0) remainingChars += charSets.numbers;
        if (settings.special > 0) remainingChars += charSets.special;

        if (!remainingChars) {
          remainingChars = Object.values(charSets).join("");
        }

        password += generateRandomChars(remainingChars, settings.length - password.length);
      }

      password = shuffleString(password);

      if (excludeAmbiguous) {
        const ambiguousPattern = /[lIO01(){}\[\]]/;
        if (ambiguousPattern.test(password)) {
          console.warn("Ambiguous characters found in password:", password);
          displayMessage("Warning: Password contains ambiguous characters.", false);
          return this.generatePassword();
        } else {
          displayMessage("Password generated without ambiguous characters.", true);
        }
      }

      currentResult = {
        value: password,
        type: "password"
      };

      setResult(password);
      calculateStrength(password);
    },

    generatePassphrase: async function () {
      const errorElement = getElementById("error");
      if (errorElement) {
        errorElement.style.opacity = "0";
        errorElement.style.padding = "0";
        errorElement.style.borderLeft = "none";
      }

      if (!await loadWordList()) {
        displayMessage("Word list is empty. Unable to generate passphrase.");
        return;
      }

      const elementIds = ["word-count", "separator", "capitalize-words", "include-number", "include-special"];
      const elements = {};
      let missingElements = [];

      elementIds.forEach(id => {
        elements[id] = getElementById(id);
        if (!elements[id]) {
          missingElements.push(id);
        }
      });

      if (missingElements.length > 0) {
        displayMessage(`Missing interface elements: ${missingElements.join(", ")}. Please refresh the page.`);
        return;
      }

      const wordCount = parseInt(sanitizeInput(elements['word-count'].value)) || 4;
      const separatorMap = {
        'hyphen': '-',
        'dot': '.',
        'underscore': '_',
        'space': ' ',
        'none': ''
      };
      const separator = separatorMap[elements.separator.value] || '-';
      const capitalizeWords = elements['capitalize-words'].checked;
      const includeNumber = elements['include-number'].checked;
      const includeSpecial = elements['include-special'].checked;

      if (!isValidNumber(wordCount, 1, 100)) {
        displayMessage("Word count must be between 1 and 100.");
        return;
      }

      let words = [];
      for (let i = 0; i < wordCount; i++) {
        const randomIndex = getSecureRandom(wordList.length);
        let word = wordList[randomIndex];
        if (capitalizeWords) {
          word = word.charAt(0).toUpperCase() + word.slice(1);
        }
        words.push(word);
      }

      let passphrase = words.join(separator);
      if (includeNumber) {
        passphrase += getSecureRandom(1000);
      }
      if (includeSpecial) {
        const specialChars = "!@#$%^&*()-_=+";
        const randomIndex = getSecureRandom(specialChars.length);
        passphrase += specialChars.charAt(randomIndex);
      }

      currentResult = {
        value: passphrase,
        type: "passphrase"
      };

      setResult(passphrase);
      calculateStrength(passphrase);
    },

    generateUsername: async function () {
      const errorElement = getElementById("error");
      if (errorElement) {
        errorElement.style.opacity = "0";
        errorElement.style.padding = "0";
        errorElement.style.borderLeft = "none";
      }

      if (!await loadWordList()) {
        return;
      }

      const elementIds = ["username-length", "username-word-count", "include-number-username", "all-lowercase"];
      const elements = {};
      let missingElements = [];

      elementIds.forEach(id => {
        elements[id] = getElementById(id);
        if (!elements[id]) {
          missingElements.push(id);
        }
      });

      if (missingElements.length > 0) {
        displayMessage(`Missing interface elements: ${missingElements.join(", ")}. Please refresh the page.`);
        return;
      }

      const length = parseInt(sanitizeInput(elements['username-length'].value)) || 10;
      const wordCount = parseInt(sanitizeInput(elements['username-word-count'].value)) || 2;
      const includeNumber = elements['include-number-username'].checked;
      const allLowercase = elements['all-lowercase'].checked;

      if (!isValidNumber(length, 1, 100) || !isValidNumber(wordCount, 1, 50)) {
        displayMessage("Length must be 1-100, word count must be 1-50.");
        return;
      }

      let words = [];
      let totalLength = 0;

      for (let i = 0; i < wordCount; i++) {
        const randomIndex = getSecureRandom(wordList.length);
        const word = wordList[randomIndex];
        words.push(word);
        totalLength += word.length;
      }

      let username = words.join("");
      if (includeNumber) {
        const maxDigits = Math.min(4, Math.max(1, length - username.length));
        const number = getSecureRandom(Math.pow(10, maxDigits));
        username += number;
        if (username.length > length) {
          username = username.substring(0, length);
        }
      } else if (username.length > length) {
        username = username.substring(0, length);
      }

      if (allLowercase) {
        username = username.toLowerCase();
      }

      currentResult = {
        value: username,
        type: "username"
      };

      setResult(username);
    },

    getCurrentResult: function () {
      return { ...currentResult };
    },

    clearResult: function () {
      currentResult = { value: "", type: "" };
      const outputElement = getElementById("output");
      if (outputElement) {
        outputElement.classList.add("hidden");
      }
    }
  };
})();

document.addEventListener("DOMContentLoaded", () => {
  StarpassApp.init();
});
