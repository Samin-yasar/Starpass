# ⭐ Starpass Generator (Beta)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Starpass Generator is a **not-for-profit, open-source** web application designed to generate secure passwords, passphrases, and usernames locally in your browser. Built with a **zero-knowledge architecture**, Starpass ensures no data is collected, stored, or transmitted, providing a privacy-focused solution for credential generation. It operates as a Progressive Web App (PWA) for offline use and is licensed under the [GNU General Public License Version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0).

Starpass uses the [**zxcvbn**](https://github.com/dropbox/zxcvbn) library for password strength assessment and a structured local word dataset (`src/common_wordslist.json`) for passphrase/username generation. The dataset is categorized by word length and semantic roles (e.g., adjectives, nouns, verbs) to improve output quality and readability.

## Features

- **Password Generation**: Create customizable passwords with:
  - Adjustable length (default: 16 characters).
  - Options for lowercase letters, uppercase letters, numbers, and special characters.
  - Exclude ambiguous characters (e.g., `l`, `I`, `O`, `()`, `[]`, `{}`).
- **Passphrase Generation**: Generate secure passphrases using role-based word combinations with:
  - Customizable word count (default: 4 words).
  - Choice of separators (hyphen, dot, underscore, space, or none).
  - Options to capitalize words or append numbers/special characters.
- **Username Generation**: Combine complete words to create readable usernames with:
  - Exact target length (default: 12 characters).
  - Role-based templates (e.g., adjective+noun, noun+verb+noun) for valid combinations.
  - Options for lowercase or appending numbers.
- **Strength Analysis**: Evaluate credential strength using zxcvbn, which assesses patterns, common words, and entropy.
- **Zero-Knowledge Architecture**: All processing occurs locally, with no cookies, tracking, or analytics.
- **Progressive Web App (PWA)**: Install for offline use via supported browsers (e.g., Chrome, Edge).
- **Theme Support**: Toggle between standard and high-contrast themes.
- **Future Features**: Save to history and integration with StarryCrypt (coming soon).

## Installation

Starpass Generator is a browser-based application that can be used online or installed as a PWA for offline access.

### Using Online
1. Visit the Starpass Generator at [https://starpass.samin-yasar.dev](https://starpass.samin-yasar.dev) (update with actual hosted URL if available).
2. Use the interface to generate passwords, passphrases, or usernames.

### Installing as a PWA
1. Open Starpass in a supported browser (e.g., Chrome, Edge).
2. Follow the browser’s prompt to install the PWA (usually via an "Install" or "Add to Home Screen" option).
3. Access Starpass offline from your device’s app menu or home screen.

### Running Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/Samin-yasar/Starpass.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Starpass
   ```
3. Install dependencies (including zxcvbn):
   ```bash
   npm install zxcvbn
   ```
4. Open `index.html` in a web browser or serve it using a local server (e.g., with Python):
   ```bash
   python -m http.server 8000
   ```
5. Access at `http://localhost:8000`.

> **Note**: The generator uses `src/common_wordslist.json`, which now includes categorized word-length buckets and semantic word groups used by both passphrase and username generation.

## Usage

1. **Generate a Password**:
   - Set the desired password length and select character types (lowercase, uppercase, numbers, special characters).
   - Optionally exclude ambiguous characters.
   - Click "Generate Password" to create and view the result.
2. **Generate a Passphrase**:
   - Choose the number of words and separator type.
   - Enable options like capitalization or appending numbers/special characters.
   - Click "Generate Passphrase" to view the result.
3. **Generate a Username**:
   - Set the target length and word count.
   - Choose case settings or append a number.
   - Click "Generate Username" to view the result.
4. **Strength Analysis**:
   - View real-time feedback on credential strength (in development) using zxcvbn, which evaluates patterns like dictionary words, keyboard sequences, and repetitions.[](https://github.com/dropbox/zxcvbn)
5. **Copy Results**: Use the "Copy to Clipboard" button to save generated credentials.
6. **Toggle Themes**: Switch between standard and high-contrast modes for accessibility.

> **Note**: Starpass is in **beta**, and features like strength analysis and save functionality are under development. Expect potential bugs or incomplete features.

## Privacy and Data Handling

Starpass operates with a **zero-knowledge architecture**, ensuring:
- All generation and processing occur locally in your browser or PWA.
- No personal data (e.g., credentials, IP address) is collected, stored, or transmitted.
- No cookies, trackers, or analytics are used.
- Support requests (e.g., via email) are the only instance where voluntarily provided data is processed, with minimal retention.

For details, see the [Privacy Notice](policy/privacy-notice.html).

## Terms of Service and Disclaimer

By using Starpass, you agree to the [Terms of Service](policy/terms-of-service.html), which outline:
- Compliance with the GPLv3 license.
- Lawful use and user responsibilities for securing generated credentials.
- Beta status limitations and "as is" provision.
- Contact information for support.

Additionally, review the [Disclaimer](policy/disclaimer.html) for important information about limitations of liability and the beta nature of the application.

## Technical Details

- **Password Strength Assessment**: Starpass integrates the [zxcvbn](https://github.com/dropbox/zxcvbn) library (MIT-licensed) for realistic password strength estimation. zxcvbn evaluates passwords against common patterns (e.g., dictionary words, keyboard patterns, repetitions) and provides a score (0-4) with feedback on crack time and suggestions for improvement.[](https://github.com/dropbox/zxcvbn)[](https://dev.to/tooleroid/password-strength-testing-with-zxcvbn-a-deep-dive-into-modern-password-security-2hl8)
- **Passphrase and Username Word Data**: `src/common_wordslist.json` is organized into multiple layers:
  - **Length buckets** (3-letter, 4-letter, 5-letter, 6-letter, and more) for length-aware generation.
  - **Semantic categories** (adjectives, nouns, verbs, connectors) for meaningful combinations.
  - **Role templates** used to build coherent passphrases and readable usernames.

## Contributing

St starrypass is open-source under the GPLv3, and contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request on [GitHub](https://github.com/Samin-yasar/Starpass).

Please ensure contributions adhere to the GPLv3 and do not introduce malicious code. Contributions to enhance zxcvbn integration or wordlist usage are particularly welcome.

## License

Starpass Generator is licensed under the [GNU General Public License Version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0). You are free to use, modify, and distribute the code, provided you adhere to the license terms, including distributing source code under the same license.

## Support

For questions, bug reports, or feedback, contact:
- **Email**: [contact@samin-yasar.dev](mailto:contact@samin-yasar.dev)
- **Contact Form**: [samin-yasar.dev/#contact](samin-yasar.dev/#contact)
- **GitHub Issues**: [https://github.com/Samin-yasar/Starpass/issues](https://github.com/Samin-yasar/Starpass/issues)

## Roadmap

- Complete strength analysis feature using zxcvbn.
- Implement "Save to History" functionality.
- Add integration with StarryCrypt.
- Enhance PWA stability and compatibility.
- Expand accessibility options.

## Acknowledgments

Developed by [Samin Yasar](https://samin-yasar.dev/) as a community-driven, not-for-profit project. Thanks to:
- [Dropbox](https://github.com/dropbox/zxcvbn) for the zxcvbn library.
- [Electronic Frontier Foundation (EFF)](https://www.eff.org) for the Long Wordlist.
- Contributors and the open-source community for supporting secure credential generation.
