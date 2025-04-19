// Live updates of password length from the slider
document.getElementById('length').addEventListener('input', (event) => {
    document.getElementById('length-value').textContent = event.target.value;
});

// Dark mode toggle
let darkMode = localStorage.getItem('darkMode') === 'true';
if (darkMode) {
    document.body.classList.add('bg-gray-800');
    document.body.classList.remove('bg-gray-100');
}

const toggleDarkMode = () => {
    darkMode = !darkMode;
    localStorage.setItem('darkMode', darkMode);
    document.body.classList.toggle('bg-gray-800', darkMode);
    document.body.classList.toggle('bg-gray-100', !darkMode);
};

// Attach dark mode toggle to button
document.getElementById('dark-mode-toggle').addEventListener('click', toggleDarkMode);

// Display error messages non-intrusively
function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
    setTimeout(() => errorDiv.classList.add('hidden'), 3000);
}

// Input validation
function validateInput(value, minValue) {
    return !isNaN(value) && value >= minValue;
}

function generatePassword() {
    // Clear previous error
    document.getElementById('error-message').classList.add('hidden');

    // Get input values
    const lowercaseCount = parseInt(document.getElementById('lowercase').value);
    const uppercaseCount = parseInt(document.getElementById('uppercase').value);
    const numbersCount = parseInt(document.getElementById('numbers').value);
    const specialCount = parseInt(document.getElementById('special').value);
    const excludeAmbiguous = document.getElementById('exclude-ambiguous').checked;
    const passwordLength = parseInt(document.getElementById('length').value);

    // Validate inputs
    if (!validateInput(lowercaseCount, 0) || !validateInput(uppercaseCount, 0) ||
        !validateInput(numbersCount, 0) || !validateInput(specialCount, 0)) {
        showError('Please enter valid non-negative numbers.');
        return;
    }

    // Validate total character count
    const totalCount = lowercaseCount + uppercaseCount + numbersCount + specialCount;
    if (totalCount > passwordLength) {
        showError('Sum of character counts exceeds password length.');
        return;
    }
    if (totalCount === 0) {
        showError('Please select at least one character type.');
        return;
    }

    // Set up possible characters
    let lowercase = 'abcdefghijklmnopqrstuvwxyz';
    let uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let numbers = '0123456789';
    let special = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    // Remove ambiguous characters if checked
    if (excludeAmbiguous) {
        lowercase = lowercase.replace(/[l]/g, '');
        uppercase = uppercase.replace(/[IO]/g, '');
        special = special.replace(/[(){}\[\]]/g, '');
    }

    // Generate password
    let password = '';
    password += getRandomChars(lowercase, lowercaseCount);
    password += getRandomChars(uppercase, uppercaseCount);
    password += getRandomChars(numbers, numbersCount);
    password += getRandomChars(special, specialCount);

    // Fill remaining length with random characters
    if (password.length < passwordLength) {
        const remainingChars = lowercase + uppercase + numbers + special;
        password += getRandomChars(remainingChars, passwordLength - password.length);
    }

    // Shuffle the password
    password = shuffleString(password);

    // Display password
    document.getElementById('password').innerText = password;
    document.getElementById('output').classList.remove('hidden');

    // Calculate strength and crack time
    calculateStrength(password);
    estimateCrackTime(password, lowercase, uppercase, numbers, special);
}

function getRandomChars(charSet, count) {
    if (!charSet || count <= 0) return '';
    const chars = [];
    for (let i = 0; i < count; i++) {
        chars.push(charSet.charAt(Math.floor(Math.random() * charSet.length)));
    }
    return chars.join('');
}

function shuffleString(str) {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
}

function copyPassword() {
    const password = document.getElementById('password').innerText;
    navigator.clipboard.writeText(password)
        .then(() => showError('Password copied to clipboard!'))
        .catch(() => showError('Failed to copy password'));
}

function calculateStrength(password) {
    let strength = 0;

    if (password.length >= 8) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/.test(password)) strength += 1;

    const strengthBar = document.getElementById('strength-bar-fill');
    strengthBar.setAttribute('aria-valuenow', strength * 20);

    switch (strength) {
        case 1:
        case 2:
            strengthBar.style.width = '25%';
            strengthBar.style.backgroundColor = '#e53e3e'; // Red
            break;
        case 3:
            strengthBar.style.width = '50%';
            strengthBar.style.backgroundColor = '#f6ad55'; // Yellow
            break;
        case 4:
            strengthBar.style.width = '75%';
            strengthBar.style.backgroundColor = '#38a169'; // Green
            break;
        case 5:
            strengthBar.style.width = '100%';
            strengthBar.style.backgroundColor = '#2b6cb0'; // Blue
            break;
        default:
            strengthBar.style.width = '0';
            break;
    }
}

function estimateCrackTime(password, lowercase, uppercase, numbers, special) {
    // Calculate character pool size based on used character sets
    let charPoolSize = 0;
    if (/[a-z]/.test(password)) charPoolSize += lowercase.length;
    if (/[A-Z]/.test(password)) charPoolSize += uppercase.length;
    if (/[0-9]/.test(password)) charPoolSize += numbers.length;
    if (/[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/.test(password)) charPoolSize += special.length;

    // Rough estimate: (charPoolSize^length) / (100 trillion guesses per second)
    const complexity = Math.pow(charPoolSize, password.length);
    const crackTimeSeconds = complexity / 100_000_000_000_000;
    const crackTimeYears = crackTimeSeconds / (60 * 60 * 24 * 365);

    document.getElementById('crack-time').innerText = `Approx. crack time: ${crackTimeYears.toFixed(2)} years`;
}
