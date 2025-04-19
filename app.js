function generatePassword() {
    const lowercaseCount = parseInt(document.getElementById('lowercase').value);
    const uppercaseCount = parseInt(document.getElementById('uppercase').value);
    const numbersCount = parseInt(document.getElementById('numbers').value);
    const specialCount = parseInt(document.getElementById('special').value);

    const errorDiv = document.getElementById('error');
    const outputDiv = document.getElementById('output');
    const passwordSpan = document.getElementById('password');
    const crackTimeSpan = document.getElementById('crack-time');
    const strengthBar = document.getElementById('strength-bar-fill');
    const entropyInfo = document.getElementById('entropy-info');

    // Input validation
    if (
        isNaN(lowercaseCount) || isNaN(uppercaseCount) ||
        isNaN(numbersCount) || isNaN(specialCount)
    ) {
        showError('Please enter valid numbers');
        return;
    }

    if (lowercaseCount < 0 || uppercaseCount < 0 || numbersCount < 0 || specialCount < 0) {
        showError('Counts cannot be negative');
        return;
    }

    const totalLength = lowercaseCount + uppercaseCount + numbersCount + specialCount;
    if (totalLength === 0) {
        showError('At least one character type must be selected');
        return;
    }

    if (totalLength < 8 || totalLength > 50) {
        showError('Total length must be between 8 and 50');
        return;
    }

    clearError();

    // Character sets
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    // Generate password
    const password = [];
    const randomValues = new Uint32Array(totalLength);
    crypto.getRandomValues(randomValues);
    let index = 0;

    for (let i = 0; i < lowercaseCount; i++) password.push(lowercase[randomValues[index++] % lowercase.length]);
    for (let i = 0; i < uppercaseCount; i++) password.push(uppercase[randomValues[index++] % uppercase.length]);
    for (let i = 0; i < numbersCount; i++) password.push(digits[randomValues[index++] % digits.length]);
    for (let i = 0; i < specialCount; i++) password.push(special[randomValues[index++] % special.length]);

    // Fisher-Yates Shuffle
    for (let i = password.length - 1; i > 0; i--) {
        const j = randomValues[i % randomValues.length] % (i + 1);
        [password[i], password[j]] = [password[j], password[i]];
    }

    const finalPassword = password.join('');
    passwordSpan.textContent = finalPassword;

    // Estimate crack time
    let charSetSize = 0;
    if (lowercaseCount > 0) charSetSize += 26;
    if (uppercaseCount > 0) charSetSize += 26;
    if (numbersCount > 0) charSetSize += 10;
    if (specialCount > 0) charSetSize += 32;

    const combinations = Math.pow(charSetSize, totalLength);
    const guessesPerSecond = 10_000_000_000;
    const secondsToCrack = combinations / guessesPerSecond;

    crackTimeSpan.textContent = formatCrackTime(secondsToCrack);

    // Strength bar
    const logSeconds = Math.log10(secondsToCrack + 1);
    const maxLog = Math.log10(31_536_000 * 1000); // ~1000 years
    const strengthPercent = Math.min((logSeconds / maxLog) * 100, 100);

    const barColor = strengthPercent < 33 ? 'bg-red-500'
        : strengthPercent < 66 ? 'bg-yellow-500'
        : 'bg-green-500';

    strengthBar.style.width = `${strengthPercent}%`;
    strengthBar.className = `h-full rounded-md transition-all duration-500 ease-in-out ${barColor}`;

    if (entropyInfo) {
        const entropy = Math.log2(combinations).toFixed(2);
        entropyInfo.textContent = `${entropy} bits of entropy`;
    }

    outputDiv.classList.remove('hidden');

    function showError(message) {
        errorDiv.textContent = message;
        outputDiv.classList.add('hidden');
    }

    function clearError() {
        errorDiv.textContent = '';
    }

    function formatCrackTime(seconds) {
        if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
        if (seconds < 3600) return `${(seconds / 60).toFixed(2)} minutes`;
        if (seconds < 86400) return `${(seconds / 3600).toFixed(2)} hours`;
        if (seconds < 31_536_000) return `${(seconds / 86400).toFixed(2)} days`;
        if (seconds < 31_536_000 * 100) return `${(seconds / 31_536_000).toFixed(2)} years`;
        return `${(seconds / (31_536_000 * 100)).toFixed(2)} centuries`;
    }
}

function copyPassword(event) {
    const password = document.getElementById('password').textContent;
    const btn = event.target;

    navigator.clipboard.writeText(password).then(() => {
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 1500);
    }).catch(() => {
        alert('Failed to copy password.');
    });
}
