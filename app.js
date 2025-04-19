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
    const entropyInfo = document.getElementById('entropy-info'); // Optional

    // Input validation
    if (
        isNaN(lowercaseCount) ||
        isNaN(uppercaseCount) ||
        isNaN(numbersCount) ||
        isNaN(specialCount)
    ) {
        errorDiv.textContent = 'Please enter valid numbers';
        outputDiv.classList.add('hidden');
        return;
    }
    if (lowercaseCount < 0 || uppercaseCount < 0 || numbersCount < 0 || specialCount < 0) {
        errorDiv.textContent = 'Counts cannot be negative';
        outputDiv.classList.add('hidden');
        return;
    }

    const totalLength = lowercaseCount + uppercaseCount + numbersCount + specialCount;
    if (totalLength === 0) {
        errorDiv.textContent = 'At least one character type must be selected';
        outputDiv.classList.add('hidden');
        return;
    }
    if (totalLength < 8 || totalLength > 50) {
        errorDiv.textContent = 'Total length must be between 8 and 50';
        outputDiv.classList.add('hidden');
        return;
    }

    errorDiv.textContent = '';

    // Character sets
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    // Generate password
    let password = [];
    const randomValues = new Uint32Array(totalLength);
    crypto.getRandomValues(randomValues);
    let index = 0;

    // Append characters
    for (let i = 0; i < lowercaseCount; i++) {
        password.push(lowercase[randomValues[index++] % lowercase.length]);
    }
    for (let i = 0; i < uppercaseCount; i++) {
        password.push(uppercase[randomValues[index++] % uppercase.length]);
    }
    for (let i = 0; i < numbersCount; i++) {
        password.push(digits[randomValues[index++] % digits.length]);
    }
    for (let i = 0; i < specialCount; i++) {
        password.push(special[randomValues[index++] % special.length]);
    }

    // Shuffle password (Fisher-Yates)
    for (let i = password.length - 1; i > 0; i--) {
        const j = randomValues[i % randomValues.length] % (i + 1);
        [password[i], password[j]] = [password[j], password[i]];
    }

    const finalPassword = password.join('');

    // Estimate crack time
    let charSetSize = 0;
    if (lowercaseCount > 0) charSetSize += 26;
    if (uppercaseCount > 0) charSetSize += 26;
    if (numbersCount > 0) charSetSize += 10;
    if (specialCount > 0) charSetSize += 32;

    const combinations = charSetSize ** totalLength;
    const guessesPerSecond = 10_000_000_000; // 10 billion guesses/sec
    const secondsToCrack = combinations / guessesPerSecond;

    let crackTime;
    if (secondsToCrack < 60) {
        crackTime = `${secondsToCrack.toFixed(2)} seconds`;
    } else if (secondsToCrack < 3600) {
        crackTime = `${(secondsToCrack / 60).toFixed(2)} minutes`;
    } else if (secondsToCrack < 86400) {
        crackTime = `${(secondsToCrack / 3600).toFixed(2)} hours`;
    } else if (secondsToCrack < 31_536_000) {
        crackTime = `${(secondsToCrack / 86400).toFixed(2)} days`;
    } else if (secondsToCrack < 31_536_000 * 100) {
        crackTime = `${(secondsToCrack / 31_536_000).toFixed(2)} years`;
    } else {
        crackTime = `${(secondsToCrack / (31_536_000 * 100)).toFixed(2)} centuries`;
    }

    // Strength bar visual
    const logSeconds = Math.log10(secondsToCrack + 1);
    const maxLog = Math.log10(31_536_000 * 1000); // ~1000 years
    const strengthPercent = Math.min((logSeconds / maxLog) * 100, 100);

    let barColor;
    if (strengthPercent < 33) {
        barColor = 'bg-red-500';
    } else if (strengthPercent < 66) {
        barColor = 'bg-yellow-500';
    } else {
        barColor = 'bg-green-500';
    }

    strengthBar.style.width = `${strengthPercent}%`;
    strengthBar.className = `h-full rounded-md transition-all duration-300 ${barColor}`;

    // Optional entropy info
    const entropy = Math.log2(combinations).toFixed(2);
    if (entropyInfo) entropyInfo.textContent = `${entropy} bits of entropy`;

    // Show result
    passwordSpan.textContent = finalPassword;
    crackTimeSpan.textContent = crackTime;
    outputDiv.classList.remove('hidden');
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
