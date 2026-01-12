# 🔐 Secure Crypto Library

A comprehensive TypeScript cryptography library for learning and understanding modern encryption techniques. Implements multiple encryption modes with security best practices.

## ⚠️ Disclaimer

**This library is designed for educational purposes and personal projects.**

While it implements security best practices, it has not undergone professional security audits. For production systems handling sensitive data (financial, healthcare, etc.), please use established libraries like:

- `libsodium` / `sodium-native`
- `tweetnacl`
- Native Web Crypto API

## 🎯 What You'll Learn

- **Symmetric encryption** (AES-256-GCM with password-based key derivation)
- **Asymmetric encryption** (RSA-OAEP envelope encryption)
- **Elliptic Curve Cryptography** (X25519 key exchange with ECDH)
- **Digital signatures** (Ed25519 for authentication)
- **Forward secrecy** (ephemeral keys)
- **Replay attack prevention** (timestamps)
- **Key derivation** (scrypt, HKDF)

## 📦 Installation

```bash
npm install your-crypto-library
```

## 🚀 Quick Start

### 1. Password-Based Encryption (Symmetric)

```typescript
import { encrypt, decrypt } from "your-crypto-library";

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

### 2. Public Key Encryption (RSA Envelope)

```typescript
import { encrypt, decrypt, generateRSAKeyPair } from "your-crypto-library";

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

### 3. Secure Channel (ECDH with Forward Secrecy)

```typescript
import { encrypt, decrypt, generateX25519KeyPair } from "your-crypto-library";

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

### 4. Authenticated Channel (ECDH + Ed25519 Signatures)

```typescript
import {
  encrypt,
  decrypt,
  generateAuthenticatedKeySet,
} from "your-crypto-library";

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

All modes support file encryption with streaming for memory efficiency:

```typescript
import { encrypt, decrypt } from "your-crypto-library";

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

| Feature               | Description                                     |
| --------------------- | ----------------------------------------------- |
| **Confidentiality**   | AES-256-GCM encryption                          |
| **Integrity**         | Authenticated encryption with GCM auth tags     |
| **Forward Secrecy**   | Ephemeral ECDH keys (secure-channel mode)       |
| **Authentication**    | Ed25519 signatures (authenticated-channel mode) |
| **Replay Protection** | Timestamp validation (optional)                 |
| **Key Validation**    | Automatic verification of key types and formats |
| **Version Control**   | Format versioning for backward compatibility    |

### Security Properties by Mode

| Mode                    | Confidentiality | Integrity | Authentication | Forward Secrecy |
| ----------------------- | --------------- | --------- | -------------- | --------------- |
| `symmetric-password`    | ✅              | ✅        | ❌             | N/A             |
| `sealEnvelope`          | ✅              | ✅        | ❌             | ❌              |
| `secure-channel`        | ✅              | ✅        | ❌             | ✅              |
| `authenticated-channel` | ✅              | ✅        | ✅             | ✅              |

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

// Decrypt with validation (default)
const decrypted = await decrypt(
  {
    type: "secure-channel",
    recipientPrivateKey: privKey,
    validateTimestamp: true, // default, rejects messages older than 5 minutes
  },
  encrypted.data
);
```

## 🔑 Key Management

### Generate Keys

```typescript
import {
  generateRSAKeyPair,
  generateX25519KeyPair,
  generateEd25519KeyPair,
  generateAuthenticatedKeySet,
} from "your-crypto-library";

// RSA 4096-bit for envelope encryption
const rsa = generateRSAKeyPair();

// X25519 for ECDH key exchange
const x25519 = generateX25519KeyPair();

// Ed25519 for signing
const ed25519 = generateEd25519KeyPair();

// Complete authenticated channel key set
const authenticated = generateAuthenticatedKeySet();
// Returns: { encryption: { publicKey, privateKey }, signing: { publicKey, privateKey } }
```

### Key Storage

```typescript
import { writeFileSync } from "fs";

const keys = generateX25519KeyPair();

// Store keys securely (use proper file permissions in production)
writeFileSync("bob-public.key", keys.publicKey);
writeFileSync("bob-private.key", keys.privateKey, { mode: 0o600 });
```

## 📊 API Reference

### Encryption Options

#### `symmetric-password`

```typescript
{
  type: "symmetric-password";
  password: string;          // Min 12 characters
  stream?: boolean;          // Auto-enabled for files
  strictMode?: boolean;      // Enforces strong password
}
```

#### `sealEnvelope` (RSA)

```typescript
{
  type: "sealEnvelope";
  recipientPublicKey: string;  // Base64 RSA public key
  stream?: boolean;
  strictMode?: boolean;
}
```

#### `secure-channel` (ECDH)

```typescript
{
  type: "secure-channel";
  recipientPublicKey: string;    // Base64 X25519 public key
  includeTimestamp?: boolean;    // Default: true
  stream?: boolean;
  strictMode?: boolean;
}
```

#### `authenticated-channel` (ECDH + Ed25519)

```typescript
{
  type: "authenticated-channel";
  recipientPublicKey: string;    // Base64 X25519 public key
  senderPrivateKey: string;      // Base64 Ed25519 private key
  includeTimestamp?: boolean;    // Default: true
  stream?: boolean;
  strictMode?: boolean;
}
```

### Return Types

```typescript
interface EncryptResult {
  type: "file" | "message";
  data?: string; // Hex string for messages
  outputPath?: string; // Path for files
}

interface DecryptResult {
  type: "file" | "message";
  data?: string | object; // Original data
  outputPath?: string;
  metadata?: {
    timestamp?: number; // Unix timestamp (ms)
    authenticated?: boolean; // True if signature verified
  };
}
```

## 🧪 Testing

```bash
npm test                 # Run all tests
npm run test:security    # Security-specific tests
npm run test:coverage    # Coverage report
```

Security tests include:

- Password strength validation
- Key type verification
- Replay attack prevention
- Signature tampering detection
- Data integrity checks
- Forward secrecy validation

## 🎓 Educational Notes

### Why Different Modes?

1. **symmetric-password**: Simplest, best for personal encryption with a passphrase
2. **sealEnvelope**: Classic public-key encryption, no forward secrecy
3. **secure-channel**: Modern approach with forward secrecy (like Signal/WhatsApp)
4. **authenticated-channel**: Maximum security with sender authentication

### Cryptographic Primitives Used

- **AES-256-GCM**: Authenticated encryption (confidentiality + integrity)
- **scrypt**: Password-based key derivation (resistant to brute force)
- **RSA-OAEP**: Asymmetric encryption with optimal padding
- **X25519**: Elliptic curve Diffie-Hellman key exchange
- **Ed25519**: Fast and secure digital signatures
- **HKDF**: Key derivation from shared secrets

### When to Use Each Mode?

```
symmetric-password
├─ Personal file encryption
├─ Backups
└─ Single-user scenarios

sealEnvelope (RSA)
├─ Email encryption (PGP-style)
├─ Legacy system compatibility
└─ One-way messages (no forward secrecy needed)

secure-channel (ECDH)
├─ Secure messaging between devices
├─ Forward-secret communications
└─ Modern protocols (like TLS 1.3)

authenticated-channel (ECDH + Ed25519)
├─ Critical communications requiring sender proof
├─ Signed contracts/documents
└─ Zero-trust environments
```

## 🐛 Common Issues

### "Invalid key" errors

- Ensure you're using the correct key type (RSA vs X25519 vs Ed25519)
- Verify keys are properly base64-encoded
- Check key format (should be DER, not PEM)

### "Message expired" errors

- Message is older than 5 minutes (default)
- Adjust with custom `MESSAGE_MAX_AGE_MS` or disable with `validateTimestamp: false`
- Check system clocks are synchronized

### "Unsupported version" errors

- Encrypted data format changed between library versions
- Re-encrypt data with current version

## 🤝 Contributing

This is an educational project. Contributions welcome:

- Bug fixes
- Additional cryptographic modes
- Documentation improvements
- More test cases

Please do NOT:

- Remove security checks
- Weaken encryption parameters
- Add backdoors (even "for testing")

## 📝 License

MIT License - See LICENSE file

## 🙏 Acknowledgments

Built with:

- Node.js `crypto` module (native cryptographic primitives)
- Inspired by libsodium, Signal Protocol, and modern cryptographic research

## 📚 Further Reading

- [Signal Protocol Specification](https://signal.org/docs/)
- [NIST Guidelines on Cryptography](https://csrc.nist.gov/)
- [Cryptography Engineering (Book)](https://www.schneier.com/books/cryptography_engineering/)
- [Soatok's Crypto Blog](https://soatok.blog/)

---

**Remember**: Cryptography is easy to get wrong. Use this library to learn, but use battle-tested libraries in production.
