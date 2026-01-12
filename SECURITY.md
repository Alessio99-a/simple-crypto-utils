# Security Policy

## 🎯 Purpose

This library is designed for **educational purposes** to help developers understand cryptographic concepts and implementations. While it follows security best practices, it has not undergone professional security audits.

## ⚠️ Usage Guidelines

### ✅ Recommended Use Cases

- Learning cryptography concepts
- Personal projects and experimentation
- Prototyping secure communications
- Understanding encryption modes
- Non-critical applications

### ❌ Not Recommended For

- Production systems handling sensitive data
- Financial applications (banking, payments, trading)
- Healthcare systems (HIPAA-compliant applications)
- Government or military systems
- Any system where security breach has severe consequences

### 🏢 For Production Use

Consider these battle-tested alternatives:

- **libsodium** / **sodium-native**: Comprehensive crypto library
- **tweetnacl**: Minimal, audited crypto primitives
- **Web Crypto API**: Native browser cryptography
- **node:crypto**: Node.js built-in crypto (what this library uses internally)

## 🔒 Security Features

### What This Library Provides

| Feature               | Implementation             | Notes                                                     |
| --------------------- | -------------------------- | --------------------------------------------------------- |
| **Confidentiality**   | AES-256-GCM                | Industry-standard authenticated encryption                |
| **Integrity**         | GCM authentication tags    | Detects any tampering                                     |
| **Forward Secrecy**   | Ephemeral X25519 keys      | Compromise of long-term keys doesn't affect past messages |
| **Authentication**    | Ed25519 signatures         | Proves sender identity (authenticated mode only)          |
| **Replay Protection** | Timestamps                 | Optional, configurable age limit                          |
| **Key Validation**    | Type checking              | Prevents wrong key type usage                             |
| **Password Security** | scrypt (N=16384, r=8, p=1) | Resistant to brute force                                  |

### What This Library Does NOT Provide

❌ **Sender Authentication** (except in authenticated-channel mode)

- `symmetric-password`, `sealEnvelope`, and `secure-channel` modes don't verify sender identity
- Anyone with the recipient's public key can send messages

❌ **Key Management**

- No automatic key rotation
- No secure key storage
- You're responsible for protecting private keys

❌ **Network Security**

- No protection against metadata analysis
- No protection against traffic analysis
- You need TLS/HTTPS separately

❌ **Side-Channel Protection**

- No specific defenses against timing attacks
- No specific defenses against cache attacks
- Relies on Node.js crypto module's implementations

## 🛡️ Security Recommendations

### 1. Password Security

```typescript
// ❌ WEAK - Will be rejected
password: "password123"

// ✅ GOOD
password: "MyStr0ng!Password#2024"

// ✅ BEST - Use strict mode
{
  type: "symmetric-password",
  password: "C0mpl3x!P@ssw0rd#2024",
  strictMode: true
}
```

**Requirements:**

- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, and special characters
- Consider using a password manager
- Never hardcode passwords in source code

### 2. Key Storage

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
// - Linux: Secret Service API
```

**Best Practices:**

- Store private keys with restrictive permissions (chmod 600)
- Never commit keys to version control
- Use environment variables or secure vaults (HashiCorp Vault, AWS Secrets Manager)
- Rotate keys periodically

### 3. Replay Attack Prevention

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
    validateTimestamp: true, // default, rejects messages >5 minutes old
  },
  encryptedData
);
```

### 4. Use Authenticated Channels for Critical Data

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
    senderPrivateKey: aliceSigningKey, // Proves sender
  },
  "Transfer $10,000"
);
```

### 5. Enable Strict Mode

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

## 🔍 Known Limitations

### 1. No Password Entropy Check

The library checks password length and complexity but doesn't check against common password lists or calculate actual entropy.

**Mitigation:** Use a password manager to generate strong passwords.

### 2. No Rate Limiting

No built-in protection against brute force attacks.

**Mitigation:** Implement rate limiting at application level.

### 3. No Memory Protection

Sensitive data (keys, passwords, plaintext) exists in memory and could be swapped to disk.

**Mitigation:**

- Use secure memory in production (libsodium has `sodium_mlock`)
- Clear sensitive variables when done: `password = null; crypto.randomFillSync(buffer);`

### 4. No Key Compromise Protection

If a private key is compromised, all past messages encrypted with RSA envelope mode can be decrypted.

**Mitigation:** Use `secure-channel` mode which provides forward secrecy with ephemeral keys.

### 5. Metadata Not Protected

Message size, timing, and communication patterns are visible.

**Mitigation:** Use padding, dummy traffic, or Tor/mixnets at protocol level.

## 🐛 Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email: security@yourproject.com (create this email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours.

## 🔄 Security Updates

- Check for updates regularly: `npm outdated secure-crypto-library`
- Subscribe to GitHub releases for notifications
- Review CHANGELOG.md for security-related changes

## ✅ Security Checklist for Users

Before using this library in any project:

- [ ] Understand the threat model for your application
- [ ] Choose appropriate encryption mode for your use case
- [ ] Implement proper key management
- [ ] Use strong passwords (12+ characters, complex)
- [ ] Enable strict mode for sensitive operations
- [ ] Store private keys securely (never in code)
- [ ] Implement rate limiting for decryption attempts
- [ ] Add logging for security events
- [ ] Consider professional security audit for critical systems
- [ ] Have incident response plan for key compromise
- [ ] Regular security reviews and updates

## 📚 Security Resources

### Learn More About Cryptography

- [Crypto 101](https://www.crypto101.io/) - Free introductory book
- [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/) - Dan Boneh & Victor Shoup
- [Practical Cryptography for Developers](https://cryptobook.nakov.com/)
- [Soatok's Blog](https://soatok.blog/) - Modern crypto insights

### Standards & Guidelines

- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Signal Protocol Specification](https://signal.org/docs/)

### Tools for Security Testing

- **Static Analysis:** ESLint with security plugins
- **Dependency Checking:** `npm audit`, Snyk, Dependabot
- **Penetration Testing:** Consider hiring professionals for critical systems

## 📝 Version History

### Version 1.0.0 (Current)

- Initial release with 4 encryption modes
- Password validation and key type checking
- Timestamp-based replay protection
- Authenticated channel with Ed25519 signatures

## 🙏 Acknowledgments

This library uses Node.js `crypto` module which relies on:

- **OpenSSL** - Industry-standard cryptographic library
- **BoringSSL** (in some Node.js builds) - Google's OpenSSL fork

Cryptographic primitives are implemented by these well-tested libraries, not custom implementations.

---

**Remember:** Security is a process, not a product. Stay informed, stay vigilant, and use the right tool for the job.
