// Live updates of password length from the slider
document.getElementById('length').addEventListener('input', (event) => {
    document.getElementById('length-value').textContent = event.target.value;
});

// Rark mode toggle
let darkMode = false;
const toggleDarkMode = () => {
    darkMode = !darkMode;
    if (darkMode) {
        document.body.classList.add('bg-gray-800');
        document.body.classList.remove('bg-gray-100');
    } else {
        document.body.classList.add('bg-gray-100');
        document.body.classList.remove('bg-gray-800');
    }
};

// Dynamic feedback for invalid input
function validateInput(value, minValue) {
    return value >= minValue;
}

function generatePassword() {
    // Get input values
    const lowercaseCount = parseInt(document.getElementById('lowercase').value);
    const uppercaseCount = parseInt(document.getElementById('uppercase').value);
    const numbersCount = parseInt(document.getElementById('numbers').value);
    const specialCount = parseInt(document.getElementById('special').value);
    const excludeAmbiguous = document.getElementById('exclude-ambiguous').checked;

    // Set up the possible characters
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    // Remove ambiguous characters if the checkbox is checked
    let specialChars = special;
    if (excludeAmbiguous) {
        specialChars = special.replace(/[(){}\[\]]/g, ''); // Exclude () [] {}
    }

    // Generate password
    let password = '';
    password += getRandomChars(lowercase, lowercaseCount);
    password += getRandomChars(uppercase, uppercaseCount);
    password += getRandomChars(numbers, numbersCount);
    password += getRandomChars(specialChars, specialCount);

    // Shuffle the password
    password = shuffleString(password);

    // Display password
    document.getElementById('password').innerText = password;
    document.getElementById('output').classList.remove('hidden');

    // Optionally, calculate password strength and crack time
    calculateStrength(password);
    estimateCrackTime(password);
}

function getRandomChars(charSet, count) {
    let chars = '';
    for (let i = 0; i < count; i++) {
        chars += charSet.charAt(Math.floor(Math.random() * charSet.length));
    }
    return chars;
}

function shuffleString(str) {
    return str.split('').sort(() => Math.random() - 0.5).join('');
}

function copyPassword() {
    const password = document.getElementById('password').innerText;
    navigator.clipboard.writeText(password);
}

function calculateStrength(password) {
    let strength = 0;

    if (password.length >= 8) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/.test(password)) strength += 1;

    const strengthBar = document.getElementById('strength-bar-fill');
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

function estimateCrackTime(password) {
    const complexity = Math.pow(94, password.length); // Assuming 94 printable characters
    const crackTime = complexity / 1000000000000000000; // Rough estimate (simplified)
    document.getElementById('crack-time').innerText = `Approximate time: ${crackTime.toFixed(2)} years`;
}
