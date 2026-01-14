# 🔐 Secure Crypto Toolkit

A comprehensive TypeScript cryptography toolkit for learning and understanding modern encryption, authentication, and security techniques. Implements multiple encryption modes, password utilities, OTP generation, and more with security best practices.

## ⚠️ DISCLAIMER

**THIS LIBRARY IS PROVIDED FOR EDUCATIONAL AND PERSONAL USE ONLY.**

**THE AUTHOR(S) ACCEPT NO RESPONSIBILITY OR LIABILITY WHATSOEVER FOR:**

- Any security vulnerabilities or weaknesses in this code
- Data loss, corruption, or unauthorized access resulting from use of this library
- Any damages, direct or indirect, arising from the use of this software
- Compliance with security standards, regulations, or legal requirements
- Production use of this library in any context

**This library has NOT undergone professional security audits.** While it implements modern cryptographic practices, it may contain bugs, implementation flaws, or design weaknesses.

**For production systems handling sensitive data** (financial, healthcare, personal information, etc.), **you MUST use established, audited libraries:**

- `libsodium` / `sodium-native`
- `tweetnacl`
- Native Web Crypto API
- `bcrypt` / `argon2` for password hashing
- `otplib` for production OTP systems

**BY USING THIS SOFTWARE, YOU AGREE THAT:**

- You use it entirely at your own risk
- The author(s) have no obligation to provide support, updates, or security patches
- You are solely responsible for evaluating the security implications of using this code
- This library is intended for learning, experimentation, and low-risk personal projects only

## 🎯 What You'll Learn

### Encryption & Key Exchange

- **Symmetric encryption** (AES-256-GCM with password-based key derivation)
- **Asymmetric encryption** (RSA-OAEP envelope encryption)
- **Elliptic Curve Cryptography** (X25519 key exchange with ECDH)
- **Digital signatures** (Ed25519 for authentication)
- **Forward secrecy** (ephemeral keys)
- **Replay attack prevention** (timestamps)
- **Key derivation** (scrypt, HKDF)

### Authentication & Identity

- **Secure password generation** (cryptographically random)
- **Password hashing and verification** (scrypt with automatic salt generation)
- **UUID generation** (v4, cryptographically random)
- **OTP generation** (HOTP and TOTP for 2FA)
- **HMAC-based authentication**

### Utilities

- **Cryptographic hashing** (SHA-256, SHA-512, etc.)
- **HMAC operations** (keyed-hash message authentication)
- **Secure random number generation**

### 🔐 See SECURITY.md for:

- Threat model
- Known limitations
- Security recommendations

## 📦 Installation

```bash
npm install your-crypto-toolkit
```

## 🚀 Quick Start

### 1. Password-Based Encryption (Symmetric)

```typescript
import { encrypt, decrypt } from "your-crypto-toolkit";

// Encrypt
const encrypted = await encrypt(
  { type: "symmetric-password", password: "MyStr0ng!Pass123" },
  "Secret message"
);

// Decrypt
const decrypted = await decrypt(
  { type: "symmetric-password", password: "MyStr0ng!Pass123" },
  encrypted.data
);

console.log(decrypted.data); // "Secret message"
```

### 2. Password Management

```typescript
import {
  generatePassword,
  hashPassword,
  verifyPassword,
} from "your-crypto-toolkit";

// Generate secure password
const password = generatePassword(16); // "aB3$xK9@mPq2#R5z"

// Hash password for storage
const hashed = await hashPassword("user_password_123");
// Returns: "scrypt$16384$8$1$<salt>$<hash>"

// Verify password
const isValid = await verifyPassword("user_password_123", hashed);
console.log(isValid); // true
```

### 3. Two-Factor Authentication (OTP/TOTP)

```typescript
import { generateOTP, generateTOTP } from "your-crypto-toolkit";

// Generate one-time password (HOTP)
const otp = generateOTP(); // "123456"

// Generate time-based OTP (TOTP)
const secret = "BASE32ENCODEDSECRET";
const totp = generateTOTP(secret); // "654321" (changes every 30s)

// NOT YET IMPLEMENTED
// Verify TOTP with time window
const isValid = verifyTOTP(secret, "654321", { window: 1 });
console.log(isValid); // true if within time window
```

### 4. UUID Generation

```typescript
import { generateUUID } from "your-crypto-toolkit";

const id = generateUUID();
console.log(id); // "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

### 5. Hashing & HMAC

```typescript
import { hash, hmac } from "your-crypto-toolkit";

// Hash data
const dataHash = hash("sensitive data", "sha256");

// Create HMAC for authentication
const signature = hashHmac("message", "secret-key", "sha256");

// Verify HMAC
const signature = hashHmac(hashedMessage, "secret-key", "sha256");
```

### 6. Signature

```typescript
// Using the class Key (recommend)
import { Key } from "your-crypto-toolkit";

const keys = await Key.generate("sign");
console.log(keys);
// {publicKey:"Mc....", privateKey:"Mc....."}
```

### 7. Public Key Encryption (RSA Envelope)

```typescript
import { encrypt, decrypt, generateRSAKeyPair } from "your-crypto-toolkit";

// Generate keys
const { publicKey, privateKey } = generateRSAKeyPair();

// Encrypt for recipient
const encrypted = await encrypt(
  { type: "sealEnvelope", recipientPublicKey: publicKey },
  "Confidential data"
);

// Decrypt
const decrypted = await decrypt(
  { type: "openEnvelope", recipientPrivateKey: privateKey },
  encrypted.data
);
```

### 8. Secure Channel (ECDH with Forward Secrecy)

```typescript
import { encrypt, decrypt, generateX25519KeyPair } from "your-crypto-toolkit";

// Bob generates keys
const bob = generateX25519KeyPair();

// Alice sends to Bob
const encrypted = await encrypt(
  { type: "secure-channel", recipientPublicKey: bob.publicKey },
  "Private message"
);

// Bob decrypts
const decrypted = await decrypt(
  { type: "secure-channel", recipientPrivateKey: bob.privateKey },
  encrypted.data
);
```

### 9. Authenticated Channel (ECDH + Ed25519 Signatures)

```typescript
import {
  encrypt,
  decrypt,
  generateAuthenticatedKeySet,
} from "your-crypto-toolkit";

// Generate keys for both parties
const alice = generateAuthenticatedKeySet();
const bob = generateAuthenticatedKeySet();

// Alice sends authenticated message to Bob
const encrypted = await encrypt(
  {
    type: "authenticated-channel",
    recipientPublicKey: bob.encryption.publicKey,
    senderPrivateKey: alice.signing.privateKey,
  },
  "Authenticated message"
);

// Bob verifies and decrypts
const decrypted = await decrypt(
  {
    type: "authenticated-channel",
    recipientPrivateKey: bob.encryption.privateKey,
    senderPublicKey: alice.signing.publicKey,
  },
  encrypted.data
);

console.log(decrypted.metadata.authenticated); // true
```

## 📁 File Encryption

All encryption modes support file encryption with streaming for memory efficiency:

```typescript
import { encrypt, decrypt } from "your-crypto-toolkit";

// Encrypt file
await encrypt(
  { type: "symmetric-password", password: "SecurePass123!" },
  undefined,
  "./sensitive.pdf",
  "./sensitive.pdf.enc"
);

// Decrypt file
await decrypt(
  { type: "symmetric-password", password: "SecurePass123!" },
  undefined,
  "./sensitive.pdf.enc",
  "./sensitive-decrypted.pdf"
);
```

## 🔒 Security Features

### ✅ What This Library Provides

| Feature                 | Description                                     |
| ----------------------- | ----------------------------------------------- |
| **Confidentiality**     | AES-256-GCM encryption                          |
| **Integrity**           | Authenticated encryption with GCM auth tags     |
| **Forward Secrecy**     | Ephemeral ECDH keys (secure-channel mode)       |
| **Authentication**      | Ed25519 signatures (authenticated-channel mode) |
| **Replay Protection**   | Timestamp validation (optional)                 |
| **Key Validation**      | Automatic verification of key types and formats |
| **Version Control**     | Format versioning for backward compatibility    |
| **Password Protection** | scrypt KDF with automatic salt generation       |
| **Secure Random**       | Cryptographically secure random generation      |
| **Time-based Security** | TOTP with configurable time windows             |

### Security Properties by Feature

#### Encryption Modes

| Mode                    | Confidentiality | Integrity | Authentication | Forward Secrecy |
| ----------------------- | --------------- | --------- | -------------- | --------------- |
| `symmetric-password`    | ✅              | ✅        | ❌             | N/A             |
| `sealEnvelope`          | ✅              | ✅        | ❌             | ❌              |
| `secure-channel`        | ✅              | ✅        | ❌             | ✅              |
| `authenticated-channel` | ✅              | ✅        | ✅             | ✅              |

#### Authentication Features

| Feature             | Algorithm | Use Case                     |
| ------------------- | --------- | ---------------------------- |
| Password Hashing    | scrypt    | User authentication          |
| HOTP                | HMAC-SHA1 | Counter-based 2FA            |
| TOTP                | HMAC-SHA1 | Time-based 2FA (Google Auth) |
| UUID                | Random v4 | Unique identifiers           |
| Password Generation | Random    | Secure password creation     |

## 🛡️ Strict Mode

Enable strict mode for maximum security enforcement:

```typescript
const encrypted = await encrypt(
  {
    type: "symmetric-password",
    password: "pass",
    strictMode: true, // Enforces strong passwords, all validations
  },
  "data"
);
```

Strict mode enforces:

- Strong password requirements (uppercase, lowercase, numbers, special chars)
- Timestamp validation (prevents replay attacks)
- All security checks enabled

## ⏱️ Replay Attack Prevention

Secure and authenticated channels include timestamps by default:

```typescript
// Encrypt with timestamp (default)
const encrypted = await encrypt(
  {
    type: "secure-channel",
    recipientPublicKey: pubKey,
    includeTimestamp: true, // default
  },
  "time-sensitive data"
);

// Decrypt with validation (default: 5 minute window)
const decrypted = await decrypt(
  {
    type: "secure-channel",
    recipientPrivateKey: privKey,
    validateTimestamp: true, // default
  },
  encrypted.data
);
```

## 🔑 API Reference

### Password Utilities

```typescript
// Generate cryptographically secure password
generatePassword(length: number = 16, options?: {
  uppercase?: boolean;    // Default: true
  lowercase?: boolean;    // Default: true
  numbers?: boolean;      // Default: true
  symbols?: boolean;      // Default: true
}): string

// Hash password with scrypt
hashPassword(password: string, options?: {
  N?: number;            // CPU/memory cost (default: 16384)
  r?: number;            // Block size (default: 8)
  p?: number;            // Parallelization (default: 1)
  keylen?: number;       // Output length (default: 32)
}): Promise<string>

// Verify password against hash
verifyPassword(password: string, hash: string): Promise<boolean>
```

### OTP/TOTP

```typescript
// Generate HMAC-based OTP
generateOTP(secret: string, counter: number, digits?: number): string

// Generate time-based OTP
generateTOTP(secret: string, options?: {
  time?: number;         // Unix timestamp (default: Date.now())
  step?: number;         // Time step in seconds (default: 30)
  digits?: number;       // OTP length (default: 6)
}): string

// Verify TOTP with time window
verifyTOTP(secret: string, token: string, options?: {
  time?: number;
  step?: number;
  window?: number;       // Allow ±N time steps (default: 1)
}): boolean
```

### Hashing & HMAC

```typescript
// Hash data
hash(data: string, algorithm?: string): string // Default: sha256

// Generate HMAC
hmac(data: string, key: string, algorithm?: string): string // Default: sha256
```

### UUID

```typescript
// Generate UUID v4
generateUUID(): string
```

### Encryption Options

_(See original documentation for encryption options)_

## 🧪 Testing

```bash
npm test                 # Run all tests
npm run test:security    # Security-specific tests
npm run test:coverage    # Coverage report
npm run test:password    # Password utility tests
npm run test:otp         # OTP/TOTP tests
```

## 🎓 Educational Notes

### When to Use Each Feature?

```
Encryption
├─ symmetric-password: Personal file encryption, backups
├─ sealEnvelope: Email encryption, legacy compatibility
├─ secure-channel: Secure messaging, forward secrecy
└─ authenticated-channel: Critical communications, signed documents

Authentication
├─ Password hashing: User account security
├─ HOTP: Hardware tokens, API counters
├─ TOTP: Mobile 2FA apps (Google Authenticator)
└─ HMAC: API signatures, webhook verification

Utilities
├─ UUID: Database IDs, session tokens
├─ Password generation: Temporary passwords, API keys
└─ Hashing: Data integrity, checksums
```

### Cryptographic Primitives Used

- **AES-256-GCM**: Authenticated encryption
- **scrypt**: Password-based key derivation (memory-hard)
- **RSA-OAEP**: Asymmetric encryption
- **X25519**: Elliptic curve Diffie-Hellman
- **Ed25519**: Digital signatures
- **HMAC-SHA1/SHA256**: Message authentication
- **HKDF**: Key derivation from shared secrets
- **CSPRNG**: Cryptographically secure random generation

## 🐛 Common Issues

### Password Issues

- **Weak password errors**: Use `strictMode: false` for testing or generate with `generatePassword()`
- **Hash verification fails**: Ensure you're using the same scrypt parameters

### OTP Issues

- **TOTP mismatch**: Check system time synchronization (NTP)
- **Time window errors**: Increase `window` parameter for clock drift

### Encryption Issues

- **Invalid key errors**: Ensure correct key type (RSA vs X25519 vs Ed25519)
- **Message expired errors**: Message older than 5 minutes or clocks not synchronized

## 🛠️ Development

### For Contributors

```bash
# Clone repository
git clone https://github.com/yourusername/crypto-toolkit.git
cd crypto-toolkit

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Check coverage
npm run test:coverage
```

### Project Structure

```
src/
|-- crypto/
|   |-- encrypt.ts           # Encryption logic
|   |-- decrypt.ts           # Decryption logic
|   |-- index.ts             # Export point and class Crypto
├── hash/
|   |-- hash.ts              # Simple hashign
|   |-- hashHmac.ts          # Hashing using hmac
|   |-- verifyHmac.ts        # Verify hmac hash time safe
|   |-- index.ts             # Export point no class for the moment
├── keys.ts
|   |-- aes.ts               # Generation random aes key & iv
|   |-- authenticate.ts      # Generation X25519 key pair & Ed25519 key pair
|   |-- ecdh.ts              # Generation X25519 key pair
|   |-- ed25519.ts           # Generation ED25519 key pair
|   |-- rsa.ts               # Generation RSA key pair
|   |-- x25519.ts            # Generation X25519 key pair
|   |-- index.ts             # Export point and class Key
├── otp
|   |-- otp.ts               # Generation OTP (no hash or verify for the moment)
|   |-- totp.ts              # Generation TOTP (no verify for the moment)
|   |-- index.ts             # Export point no class for the moment
├── password
|   |-- generate.ts          # Generation safe & random password
|   |-- hash.ts              # Hashing the password with scrypt
|   |-- verify.ts            # Verify the hashed password
|   |-- index.ts             # Export point no class for the moment
├── signature
|   |-- sign.ts             # Sign logic
|   |-- verify.ts           # Verify logic
|   |-- index.ts            # Export point and class Signer
├── index.ts            # Public API
└── examples.ts         # Examples  functions
```

### Generate Test Keys

Create a script to generate keys for testing:

```typescript
// generate-keys.js
import { Key } from "your-crypto-toolkit";

const fs = require("fs");

// Create keys directory
if (!fs.existsSync("./keys")) {
  fs.mkdirSync("./keys", { mode: 0o700 });
}

// Generate keys
const rsa = Key.generate("seal");
const x25519 = Key.generate("secure-channel");
const auth = Key.generate("sign");

// Save keys (restrict permissions)
fs.writeFileSync("./keys/rsa-public.key", rsa.publicKey);
fs.writeFileSync("./keys/rsa-private.key", rsa.privateKey, { mode: 0o600 });
fs.writeFileSync("./keys/x25519-public.key", x25519.publicKey);
fs.writeFileSync("./keys/x25519-private.key", x25519.privateKey, {
  mode: 0o600,
});

console.log("✅ Keys generated in ./keys/");
```

**Important:** Add to `.gitignore`:

```
keys/
*.key
.env
```

### Environment Variables

For testing, create `.env` (don't commit):

```bash
# Test credentials (NOT for production)
TEST_PASSWORD=TestPassword123!
TOTP_TEST_SECRET=JBSWY3DPEHPK3PXP

# Node environment
NODE_ENV=development
```

### Running Examples

```bash
# Run example file
node dist/examples.js

# Or with ts-node
npx ts-node src/examples.ts
```

### Publishing

```bash
# Login to npm
npm login

# Dry run
npm publish --dry-run

# Publish
npm publish
```

## 🤝 Contributing

This is an educational project. Contributions welcome:

- Bug fixes
- Additional cryptographic features
- Documentation improvements
- More test cases
- Security analysis reports

Please do NOT:

- Remove security checks
- Weaken cryptographic parameters
- Add backdoors or intentional vulnerabilities

### Contributing Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Write tests for new features
4. Ensure all tests pass (`npm test`)
5. Update documentation
6. Submit pull request

**Don't:**

- Remove security checks
- Weaken cryptographic parameters
- Add backdoors or vulnerabilities
- Commit private keys or secrets

## 📝 License

MIT License

Copyright (c) [2026] [Alessio Galtelli]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.**

## 🙏 Acknowledgments

Built with:

- Node.js `crypto` module (native cryptographic primitives)
- Inspired by libsodium, Signal Protocol, OWASP guidelines, and RFC specifications

Educational resources:

- [RFC 4226 (HOTP)](https://tools.ietf.org/html/rfc4226)
- [RFC 6238 (TOTP)](https://tools.ietf.org/html/rfc6238)
- [Signal Protocol Specification](https://signal.org/docs/)
- [NIST Guidelines on Cryptography](https://csrc.nist.gov/)

## 📚 Further Reading

- [Cryptography Engineering (Book)](https://www.schneier.com/books/cryptography_engineering/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Soatok's Crypto Blog](https://soatok.blog/)

---

**⚠️ FINAL REMINDER**: This library is for learning and experimentation. Cryptography is extremely difficult to implement correctly. For anything important, use professionally audited libraries. The authors accept absolutely no responsibility for any consequences of using this code.
