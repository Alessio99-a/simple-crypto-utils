# Security Policy

## 🎯 Purpose

This library is designed for **educational purposes** to help developers understand cryptographic concepts and implementations. While it follows security best practices, it has not undergone professional security audits.

## ⚠️ DISCLAIMER

**THE AUTHOR(S) ACCEPT NO LIABILITY OR RESPONSIBILITY FOR:**

- Security vulnerabilities or weaknesses in this code
- Data loss, corruption, or unauthorized access
- Any damages arising from use of this software
- Production use in critical systems

**This library has NOT been professionally audited.** Use established, audited libraries for production systems.

## 📋 Usage Guidelines

### ✅ Recommended Use Cases

- Learning cryptography concepts
- Personal projects and experimentation
- Prototyping secure communications
- Understanding encryption modes and authentication
- Non-critical applications

### ❌ Not Recommended For

- Production systems handling sensitive data
- Financial applications (banking, payments, trading)
- Healthcare systems (HIPAA compliance)
- Government or military systems
- Any system where security breach has severe consequences
- Identity verification systems
- Critical infrastructure

### 🏢 For Production Use

Use these battle-tested alternatives:

**Encryption & Key Exchange:**

- `libsodium` / `sodium-native`
- `tweetnacl`
- Native Web Crypto API
- `node:crypto` (native Node.js)

**Password Hashing:**

- `bcrypt`
- `argon2` (recommended for new projects)
- `scrypt` (via native crypto)

**OTP/TOTP:**

- `otplib`
- `speakeasy`
- `node-otp`

## 🔒 Security Features

### What This Library Provides

#### Encryption & Key Exchange

| Feature               | Implementation          | Notes                                               |
| --------------------- | ----------------------- | --------------------------------------------------- |
| **Confidentiality**   | AES-256-GCM             | Industry-standard authenticated encryption          |
| **Integrity**         | GCM authentication tags | Detects tampering                                   |
| **Forward Secrecy**   | Ephemeral X25519 keys   | Past messages safe if long-term keys compromised    |
| **Authentication**    | Ed25519 signatures      | Proves sender identity (authenticated-channel only) |
| **Replay Protection** | Timestamps              | Optional, configurable age limit                    |
| **Key Validation**    | Type checking           | Prevents wrong key type usage                       |

#### Password & Authentication

| Feature                 | Implementation             | Notes                                            |
| ----------------------- | -------------------------- | ------------------------------------------------ |
| **Password Hashing**    | scrypt (N=16384, r=8, p=1) | Memory-hard, resistant to brute force            |
| **Password Generation** | CSPRNG                     | Cryptographically secure random                  |
| **HOTP**                | RFC 4226 (HMAC-SHA1)       | Counter-based OTP                                |
| **TOTP**                | RFC 6238 (HMAC-SHA1)       | Time-based OTP (Google Authenticator compatible) |
| **HMAC**                | SHA-256/SHA-512            | Message authentication codes                     |
| **UUID**                | v4 (random)                | 122 bits of entropy                              |

### Security Properties by Mode

#### Encryption Modes

| Mode                    | Confidentiality | Integrity | Authentication | Forward Secrecy |
| ----------------------- | --------------- | --------- | -------------- | --------------- |
| `symmetric-password`    | ✅              | ✅        | ❌             | N/A             |
| `sealEnvelope`          | ✅              | ✅        | ❌             | ❌              |
| `secure-channel`        | ✅              | ✅        | ❌             | ✅              |
| `authenticated-channel` | ✅              | ✅        | ✅             | ✅              |

### What This Library Does NOT Provide

❌ **Sender Authentication** (except authenticated-channel mode)

- `symmetric-password`, `sealEnvelope`, `secure-channel` don't verify sender
- Anyone with recipient's public key can send messages

❌ **Password Breach Detection**

- No checking against common password lists (e.g., HaveIBeenPwned)
- No entropy calculation beyond basic complexity rules

❌ **Rate Limiting**

- No built-in brute force protection
- Must implement at application level

❌ **Key Management**

- No automatic key rotation
- No secure key storage
- No key backup/recovery
- You're responsible for protecting private keys

❌ **Network Security**

- No protection against metadata analysis
- No protection against traffic analysis
- You need TLS/HTTPS separately

❌ **Side-Channel Protection**

- No specific defenses against timing attacks
- No specific defenses against cache attacks
- Relies on Node.js crypto module's implementations

❌ **Account Security**

- No account lockout after failed attempts
- No password expiration
- No multi-factor enforcement

## 🧠 Threat Model (Simplified)

This library assumes:

- Attacker can read and modify network traffic
- Attacker cannot break modern cryptography
- Attacker may obtain encrypted messages
- Attacker may attempt replay attacks
- Attacker may attempt brute force attacks

This library does NOT protect against:

- Compromised endpoints
- Malicious runtime environments
- Physical access attacks

## 🛡️ Security Recommendations

### 1. Password Security

```typescript
// ❌ WEAK - Will be rejected in strict mode
password: "password123";

// ⚠️ ACCEPTABLE - Meets minimum requirements
password: "MyPassword123!";

// ✅ GOOD
password: "MyStr0ng!Password#2024";

// ✅ BEST - Generated password
import { generatePassword } from "simple-crypto-utils";
const password = generatePassword(20);
```

**Requirements:**

- Minimum 12 characters (16+ recommended)
- Mix of uppercase, lowercase, numbers, special characters
- Never reuse passwords across systems
- Use a password manager
- Never hardcode passwords in source code

**For Password Storage:**

```typescript
// ✅ Hash passwords before storing
const hashed = await hashPassword(userPassword);
// Store 'hashed' in database, never plaintext

// ✅ Verify on login
const isValid = await verifyPassword(userPassword, storedHash);
```

### 2. OTP/TOTP Security

```typescript
// ✅ Generate secure secrets
import { generatePassword } from "simple-crypto-utils";
const totpSecret = generatePassword(32, {
  symbols: false, // Base32 compatible
});

// ✅ Use time window for clock drift
const isValid = verifyTOTP(secret, userToken, {
  window: 1, // Allow ±30 seconds
});

// ❌ Don't use predictable secrets
const secret = "12345678"; // NEVER DO THIS
```

**Best Practices:**

- Store TOTP secrets encrypted, never plaintext
- Use QR codes for user setup (but don't log/store them)
- Implement backup codes for account recovery
- Rate limit OTP verification attempts (3-5 tries)
- Log failed OTP attempts for security monitoring

### 3. Key Storage

```typescript
// ❌ NEVER do this
const privateKey = "MCowBQYDK2VuAyEA..."; // Hardcoded!

// ✅ Load from secure storage
import { readFileSync } from "fs";
const privateKey = readFileSync("/secure/path/private.key", "utf8");

// ✅ Use environment variables
const privateKey = process.env.PRIVATE_KEY;

// ✅ Best: Use OS keychain/credential manager
// - Windows: Credential Manager
// - macOS: Keychain
// - Linux: Secret Service API / gnome-keyring
```

**Best Practices:**

- Store private keys with restrictive permissions (`chmod 600`)
- Never commit keys to version control
- Add `*.key`, `.env`, `keys/` to `.gitignore`
- Use environment variables or secure vaults (HashiCorp Vault, AWS Secrets Manager)
- Rotate keys periodically (especially after suspected compromise)
- Keep backups of keys in secure, offline storage

### 4. Replay Attack Prevention

```typescript
// ✅ Enable timestamp validation (default for secure/authenticated channels)
const encrypted = await encrypt(
  {
    type: "secure-channel",
    recipientPublicKey: pubKey,
    includeTimestamp: true, // default
  },
  "time-sensitive data"
);

const decrypted = await decrypt(
  {
    type: "secure-channel",
    recipientPrivateKey: privKey,
    validateTimestamp: true, // default, rejects >5 minutes old
  },
  encryptedData
);
```

**Considerations:**

- Ensure system clocks are synchronized (use NTP)
- Adjust time window based on network latency
- For critical operations, use shorter windows (1-2 minutes)

### 5. Use Authenticated Channels for Critical Data

```typescript
// ❌ For critical transactions, don't use unauthenticated modes
await encrypt(
  {
    type: "secure-channel", // No sender authentication!
    recipientPublicKey: bobKey,
  },
  "Transfer $10,000"
);

// ✅ Use authenticated channel
await encrypt(
  {
    type: "authenticated-channel",
    recipientPublicKey: bobKey,
    senderPrivateKey: aliceSigningKey, // Proves sender identity
  },
  "Transfer $10,000"
);
```

### 6. Enable Strict Mode

```typescript
// ✅ For maximum security
const result = await encrypt(
  {
    type: "symmetric-password",
    password: password,
    strictMode: true, // Enforces all security checks
  },
  data
);
```

Strict mode enforces:

- Strong password requirements
- Timestamp validation
- All security checks enabled

### 7. Input Validation

```typescript
// ✅ Always validate user input
function validatePassword(password: string): boolean {
  if (!password || password.length < 12) {
    throw new Error("Password must be at least 12 characters");
  }
  if (!/[A-Z]/.test(password)) {
    throw new Error("Password must contain uppercase letters");
  }
  if (!/[a-z]/.test(password)) {
    throw new Error("Password must contain lowercase letters");
  }
  if (!/[0-9]/.test(password)) {
    throw new Error("Password must contain numbers");
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    throw new Error("Password must contain special characters");
  }
  return true;
}

// ✅ Sanitize file paths
function sanitizePath(filePath: string): string {
  // Prevent path traversal
  if (filePath.includes("..") || filePath.includes("~")) {
    throw new Error("Invalid file path");
  }
  return path.resolve(filePath);
}
```

### 8. Error Handling

```typescript
// ❌ Don't leak sensitive information in errors
try {
  await decrypt(options, data);
} catch (error) {
  console.error("Decryption failed:", error.message); // Might reveal key info!
}

// ✅ Generic error messages for users
try {
  await decrypt(options, data);
} catch (error) {
  console.error("Decryption failed"); // Generic
  logger.debug("Decryption error details:", error); // Log details securely
  throw new Error("Unable to decrypt data");
}
```

## 🔍 Known Limitations

### 1. No Password Breach Database

The library checks length and complexity but doesn't verify against known breached passwords.

**Mitigation:**

- Use `haveibeenpwned.com` API for password checking
- Implement custom password blacklist
- Use a password manager

### 2. No Rate Limiting

No built-in protection against brute force attacks.

**Mitigation:**

- Implement exponential backoff (e.g., double delay after each failure)
- Lock accounts after N failed attempts
- Use CAPTCHA after multiple failures
- Monitor for suspicious patterns

### 3. No Memory Protection

Sensitive data (keys, passwords, plaintext) exists in memory and could be swapped to disk.

**Mitigation:**

- Use libsodium's `sodium_mlock` in production
- Clear sensitive variables when done: `password = null`
- Avoid storing plaintext unnecessarily
- Consider using secure enclaves (TPM, HSM) for critical keys

### 4. No Key Compromise Protection (RSA mode)

If RSA private key is compromised, all past messages can be decrypted.

**Mitigation:**

- Use `secure-channel` mode for forward secrecy
- Rotate keys regularly
- Monitor for unauthorized key access

### 5. Metadata Not Protected

Message size, timing, and communication patterns are visible.

**Mitigation:**

- Use padding to hide message sizes
- Add dummy traffic to mask patterns
- Use Tor or mixnets for network anonymity
- Implement at protocol level

### 6. Time-Based Attacks on TOTP

TOTP codes can be captured and reused within time window.

**Mitigation:**

- Implement one-time use tracking (nonce)
- Reduce time window when possible
- Use HOTP for one-time codes
- Combine with other factors

### 7. No Account Recovery

If keys or passwords are lost, data cannot be recovered.

**Mitigation:**

- Implement secure backup mechanisms
- Use key escrow for organizational systems
- Provide recovery codes
- Document backup procedures

## 🐛 Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email: Create a security contact method or use GitHub Security Advisories
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Affected versions
   - Suggested fix (if any)

**Response Time:** This is a volunteer project, but we aim to acknowledge reports within 7 days.

## 🔄 Security Updates

- Check for updates: `npm outdated simple-crypto-utils`
- Review CHANGELOG.md for security-related changes
- Enable GitHub notifications for releases
- Run `npm audit` regularly

**No Security Guarantees:** As an educational library, security patches may be delayed or not provided.

## ✅ Security Checklist

Before using this library:

**Infrastructure:**

- [ ] Understand your threat model
- [ ] Choose appropriate encryption mode
- [ ] Implement proper key management system
- [ ] Set up secure key storage (not in code/git)
- [ ] Configure environment variables properly
- [ ] Enable HTTPS/TLS for all network communication

**Authentication:**

- [ ] Use strong passwords (12+ chars, complex)
- [ ] Hash passwords before storage (never plaintext)
- [ ] Implement rate limiting (3-5 attempts)
- [ ] Add account lockout after failed attempts
- [ ] Store TOTP secrets encrypted
- [ ] Provide backup codes for 2FA recovery

**Operations:**

- [ ] Enable strict mode for sensitive operations
- [ ] Add logging for security events (exclude sensitive data)
- [ ] Implement input validation
- [ ] Sanitize error messages (don't leak details)
- [ ] Regular security reviews and updates
- [ ] Have incident response plan

**Monitoring:**

- [ ] Log failed authentication attempts
- [ ] Monitor for suspicious patterns
- [ ] Set up alerts for anomalies
- [ ] Regular audit of access logs
- [ ] Track key usage and rotation

**For Production:**

- [ ] Use audited libraries instead
- [ ] Professional security audit
- [ ] Penetration testing
- [ ] Compliance review (GDPR, HIPAA, etc.)
- [ ] Legal review of liability

## 📚 Security Resources

### Learn More About Cryptography

- [Crypto 101](https://www.crypto101.io/) - Free introductory book
- [Practical Cryptography for Developers](https://cryptobook.nakov.com/)
- [Soatok's Blog](https://soatok.blog/) - Modern crypto insights
- [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/) - Dan Boneh & Victor Shoup

### Standards & Guidelines

- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Signal Protocol Specification](https://signal.org/docs/)
- [RFC 4226 - HOTP](https://tools.ietf.org/html/rfc4226)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)

### Security Testing Tools

- **Static Analysis:** ESLint with security plugins, SonarQube
- **Dependency Checking:** `npm audit`, Snyk, Dependabot
- **Secrets Scanning:** git-secrets, truffleHog
- **Penetration Testing:** Consider hiring professionals for critical systems

## 🎓 Educational Security Principles

### Defense in Depth

Don't rely on a single security measure:

- Encryption + Authentication + Rate Limiting
- Strong passwords + 2FA + Account monitoring
- Input validation + Output sanitization + Error handling

### Principle of Least Privilege

Only grant necessary permissions:

- Private keys readable only by owner (`chmod 600`)
- Limit access to sensitive operations
- Use separate keys for different purposes

### Fail Securely

When errors occur, fail to a secure state:

- Reject invalid data rather than trying to fix it
- Clear sensitive data on error
- Don't leak information in error messages

### Keep It Simple

Complexity is the enemy of security:

- Use well-established algorithms
- Don't implement your own crypto primitives
- Prefer simple, audited solutions

## 📝 Version History

### Version 1.0.0

- Initial release with 4 encryption modes
- Password generation and hashing (scrypt)
- OTP/TOTP implementation (RFC 4226, RFC 6238)
- UUID generation (v4)
- HMAC and hashing utilities
- Password validation and key type checking
- Timestamp-based replay protection
- Authenticated channel with Ed25519 signatures

**Known Issues:**

- No rate limiting
- No password breach checking
- No key rotation automation
- See limitations section above

## 🙏 Acknowledgments

This library uses Node.js `crypto` module which relies on:

- **OpenSSL** - Industry-standard cryptographic library
- **BoringSSL** (in some Node.js builds) - Google's OpenSSL fork

Cryptographic primitives are implemented by these well-tested libraries, not custom implementations.

---

**⚠️ FINAL REMINDER:** This library is for learning and experimentation. Cryptography and security are extremely difficult to implement correctly. For anything important, use professionally audited libraries. The authors accept absolutely no responsibility for any consequences of using this code. You use this software entirely at your own risk.
