function generatePassword() {
    const lowercaseCount = +document.getElementById('lowercase').value;
    const uppercaseCount = +document.getElementById('uppercase').value;
    const numbersCount = +document.getElementById('numbers').value;
    const specialCount = +document.getElementById('special').value;
    const totalLength = lowercaseCount + uppercaseCount + numbersCount + specialCount;

    const error = document.getElementById('error');
    const output = document.getElementById('output');
    const passwordField = document.getElementById('password');
    const crackTime = document.getElementById('crack-time');
    const strengthBar = document.getElementById('strength-bar-fill');

    error.textContent = '';
    passwordField.textContent = '';
    crackTime.textContent = '';
    output.classList.add('hidden');

    if (totalLength === 0) {
        error.textContent = 'Please enter at least one character in any category.';
        return;
    }

    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+{}[]<>?/|';

    let chars = '';
    chars += getRandomChars(lowercase, lowercaseCount);
    chars += getRandomChars(uppercase, uppercaseCount);
    chars += getRandomChars(numbers, numbersCount);
    chars += getRandomChars(special, specialCount);

    const password = shuffle(chars.split('')).join('');
    passwordField.textContent = password;
    output.classList.remove('hidden');

    // Strength logic
    const entropy = estimateEntropy(password);
    const crackSeconds = Math.pow(2, entropy) / 1e9; // billion guesses/sec
    crackTime.textContent = humanizeSeconds(crackSeconds);

    const percent = Math.min((entropy / 128) * 100, 100);
    strengthBar.style.width = percent + '%';

    if (percent < 30) {
        strengthBar.className = 'bg-red-500 h-full rounded-md';
    } else if (percent < 60) {
        strengthBar.className = 'bg-yellow-400 h-full rounded-md';
    } else if (percent < 85) {
        strengthBar.className = 'bg-blue-500 h-full rounded-md';
    } else {
        strengthBar.className = 'bg-green-500 h-full rounded-md strong';
    }
}

function getRandomChars(set, count) {
    let result = '';
    for (let i = 0; i < count; i++) {
        const index = Math.floor(Math.random() * set.length);
        result += set[index];
    }
    return result;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function estimateEntropy(password) {
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^A-Za-z0-9]/.test(password)) charsetSize += 32; // approx. for special chars
    return password.length * Math.log2(charsetSize);
}

function humanizeSeconds(seconds) {
    if (seconds < 1) return 'less than 1 second';
    const units = [
        { label: 'year', seconds: 31536000 },
        { label: 'day', seconds: 86400 },
        { label: 'hour', seconds: 3600 },
        { label: 'minute', seconds: 60 },
        { label: 'second', seconds: 1 }
    ];
    for (const unit of units) {
        const value = Math.floor(seconds / unit.seconds);
        if (value >= 1) return `${value} ${unit.label}${value > 1 ? 's' : ''}`;
    }
}
