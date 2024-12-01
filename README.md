# AuthRelay

AuthRelay is a web application that simulates authentication relay processes. It is designed to help developers test and understand how authentication information, such as JWT tokens and session cookies, can be transferred to other web applications securely.

## Features

- **Multi-language Support**: Supports English and Japanese.
- **Authentication Methods**:
  - JWT (JSON Web Token)
  - Session Cookies
- **Flexible Connection Options**:
  - Include authentication in HTTP headers
  - Automatically send credentials via cookies
- **Security Features**:
  - Content Security Policy (CSP)
  - Referrer Policy
  - Permissions Policy
  - Secure cookie handling with `HttpOnly`, `SameSite`, and `Secure` attributes
- **Customizable Roles**: Predefined user roles with the option to add custom roles.
- **Algorithm Selection**: Supports various algorithms for signing JWTs (e.g., HS256, RS256).
- **Validation and Feedback**: Provides clear feedback for invalid inputs and displays request information for debugging.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/authrelay.git
   cd authrelay
   ```

2. Install dependencies:
   ```bash
   composer install
   ```

3. Configure the application:
   - Ensure `languages/` contains the necessary translation files (`en.php`, `ja.php`).
   - Update any necessary file paths for private keys.

4. Start a local server:
   ```bash
   php -S localhost:8000
   ```

5. Access the application in your browser:
   ```
   http://localhost:8000
   ```

## Usage

1. Select your preferred language using the navigation links at the bottom.
2. Fill in the required fields:
   - **User ID**: Your unique identifier.
   - **Secret Key**: Used for HMAC or RSA/EC algorithms.
   - **Redirect URL**: The destination application URL.
3. Choose your roles and authentication type.
4. Optionally, upload a private key if needed.
5. Simulate the request or connect directly.
6. Review the request information displayed at the bottom.

## Supported Algorithms

| Algorithm | Description                  |
|-----------|------------------------------|
| HS256     | HMAC with SHA-256           |
| HS384     | HMAC with SHA-384           |
| HS512     | HMAC with SHA-512           |
| RS256     | RSA with SHA-256            |
| RS384     | RSA with SHA-384            |
| RS512     | RSA with SHA-512            |
| ES256     | ECDSA with SHA-256          |
| ES384     | ECDSA with SHA-384          |

## Security Considerations

- **Content Security Policy**: Restricts sources of scripts and images.
- **Strict Headers**: Prevents common vulnerabilities such as clickjacking and MIME sniffing.
- **Secure Cookies**: Ensures cookies are sent securely and are inaccessible to JavaScript.

## Contribution

Contributions are welcome! Feel free to open issues or submit pull requests for new features, bug fixes, or translations.

### To contribute:

1. Fork the repository.
2. Create a new branch for your feature/bugfix:
   ```bash
   git checkout -b feature-name
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Add new feature"
   ```
4. Push your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**Enjoy using AuthRelay to streamline your authentication workflows!**

