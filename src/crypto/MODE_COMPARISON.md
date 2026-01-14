# Encryption Mode Comparison Guide

## 🎯 Quick Decision Tree

```
Do you need to send to someone else?
│
├─ NO → Use symmetric-password
│        (simplest, for personal use)
│
└─ YES → Do you need to prove who sent it?
          │
          ├─ NO → Can the receiver's key be compromised?
          │       │
          │       ├─ Unlikely → Use sealEnvelope (RSA)
          │       │             (simple public-key encryption)
          │       │
          │       └─ Possible → Use secure-channel (ECDH)
          │                     (forward secrecy protects past messages)
          │
          └─ YES → Use authenticated-channel (ECDH + Ed25519)
                   (proves sender identity with signature)
```

## 📊 Feature Comparison Table

| Feature                | symmetric-password | sealEnvelope | secure-channel | authenticated-channel |
| ---------------------- | ------------------ | ------------ | -------------- | --------------------- |
| **Setup Complexity**   | 🟢 Simple          | 🟡 Medium    | 🟡 Medium      | 🔴 Complex            |
| **Performance**        | 🟢 Fast            | 🔴 Slow      | 🟢 Fast        | 🟡 Medium             |
| **Confidentiality**    | ✅                 | ✅           | ✅             | ✅                    |
| **Integrity**          | ✅                 | ✅           | ✅             | ✅                    |
| **Authentication**     | ❌                 | ❌           | ❌             | ✅                    |
| **Forward Secrecy**    | N/A                | ❌           | ✅             | ✅                    |
| **Key Type**           | Password           | RSA          | X25519         | X25519 + Ed25519      |
| **Key Size**           | Variable           | 4096 bits    | 256 bits       | 512 bits total        |
| **Memory Usage**       | 🟢 Low             | 🔴 High      | 🟢 Low         | 🟡 Medium             |
| **Quantum Resistance** | ✅ (AES)           | ❌ (RSA)     | ❌ (ECDH)      | ❌ (ECDH/Ed25519)     |

Legend: 🟢 = Excellent, 🟡 = Good, 🔴 = Poor

## 🔐 Mode 1: Symmetric Password

### Overview

Traditional password-based encryption. Single shared secret (password) used for both encryption and decryption.

### Use Cases

- ✅ Personal file encryption
- ✅ Backup encryption
- ✅ Password manager vaults
- ✅ Local data protection
- ✅ Single-user scenarios

### Avoid For

- ❌ Sending to others (password sharing is risky)
- ❌ Multi-user systems
- ❌ When sender identity matters

### Technical Details

```
Encryption Algorithm: AES-256-GCM
Key Derivation: scrypt (N=16384, r=8, p=1)
Salt: 16 bytes (random per encryption)
IV: 12 bytes (random per encryption)
Auth Tag: 16 bytes (GCM)
```

### Security Considerations

- Password is the weakest link
- Vulnerable to brute force if password is weak
- No way to prove who encrypted it
- Key compromise affects all data encrypted with that password

### Example Code

```typescript
const encrypted = await encrypt(
  {
    type: "symmetric-password",
    password: "MyStr0ng!Pass123",
    strictMode: true,
  },
  "Sensitive personal data"
);

const decrypted = await decrypt(
  { type: "symmetric-password", password: "MyStr0ng!Pass123" },
  encrypted.data
);
```

---

## 🔑 Mode 2: Seal Envelope (RSA)

### Overview

Classic public-key encryption. Recipient has a key pair; anyone can encrypt to their public key, only they can decrypt with private key.

### Use Cases

- ✅ Email encryption (PGP-style)
- ✅ Sending to someone you don't communicate with regularly
- ✅ One-way secure messages
- ✅ Legacy system compatibility

### Avoid For

- ❌ Real-time messaging (too slow)
- ❌ When forward secrecy needed
- ❌ High-volume encryption

### Technical Details

```
Asymmetric: RSA-4096 with OAEP padding (SHA-256)
Symmetric: AES-256-GCM
Process:
  1. Generate random AES-256 key
  2. Encrypt data with AES-256-GCM
  3. Encrypt AES key with recipient's RSA public key
  4. Send: [encrypted AES key] + [encrypted data]
```

### Security Considerations

- **No forward secrecy**: If private key compromised, all past messages can be decrypted
- Slower than symmetric encryption
- Large key size (4096 bits)
- Quantum computers will break RSA (future threat)

### Example Code

```typescript
const { publicKey, privateKey } = generateRSAKeyPair();

const encrypted = await encrypt(
  { type: "sealEnvelope", recipientPublicKey: publicKey },
  "Confidential message"
);

const decrypted = await decrypt(
  { type: "openEnvelope", recipientPrivateKey: privateKey },
  encrypted.data
);
```

---

## 🔐 Mode 3: Secure Channel (ECDH)

### Overview

Modern approach using ephemeral keys. Each message uses a new temporary key that's discarded after encryption. Provides forward secrecy.

### Use Cases

- ✅ Secure messaging apps (Signal, WhatsApp)
- ✅ Real-time communication
- ✅ When long-term key compromise is a risk
- ✅ Modern protocols (TLS 1.3 style)

### Avoid For

- ❌ When sender authentication is critical
- ❌ Legal/compliance (no non-repudiation)

### Technical Details

```
Key Exchange: X25519 (Elliptic Curve Diffie-Hellman)
Symmetric: AES-256-GCM
Key Derivation: HKDF-SHA256
Process:
  1. Generate ephemeral X25519 key pair (sender)
  2. Compute shared secret with recipient's public key
  3. Derive AES key from shared secret using HKDF
  4. Encrypt data with AES-256-GCM
  5. Send: [ephemeral public key] + [encrypted data]
  6. Discard ephemeral private key
```

### Security Considerations

- **Forward secrecy**: Compromise of long-term keys doesn't affect past messages
- **No authentication**: Can't prove who sent the message
- Each message uses different ephemeral key (good)
- Smaller keys than RSA (256 bits vs 4096 bits)

### Example Code

```typescript
const bob = generateX25519KeyPair();

const encrypted = await encrypt(
  {
    type: "secure-channel",
    recipientPublicKey: bob.publicKey,
    includeTimestamp: true, // Replay protection
  },
  "Forward-secret message"
);

const decrypted = await decrypt(
  {
    type: "secure-channel",
    recipientPrivateKey: bob.privateKey,
    validateTimestamp: true,
  },
  encrypted.data
);
```

---

## ✍️ Mode 4: Authenticated Channel (ECDH + Ed25519)

### Overview

Most secure mode. Combines forward secrecy (ECDH) with digital signatures (Ed25519) to prove sender identity.

### Use Cases

- ✅ Critical financial transactions
- ✅ Signed contracts/documents
- ✅ Medical records (HIPAA)
- ✅ Government communications
- ✅ Any scenario needing non-repudiation

### Avoid For

- ❌ High-volume data (slight performance overhead)
- ❌ When sender wants deniability

### Technical Details

```
Encryption: X25519 ECDH + AES-256-GCM (same as secure-channel)
Signature: Ed25519
Process:
  1. Encrypt with secure-channel method (ECDH)
  2. Sign [ephemeral key + IV + auth tag] with sender's Ed25519 key
  3. Send: [encrypted data] + [signature]
  4. Recipient verifies signature before decrypting
```

### Security Considerations

- **Forward secrecy**: Yes (from ECDH)
- **Authentication**: Yes (from Ed25519 signature)
- **Non-repudiation**: Sender can't deny sending
- Requires two key pairs per party:
  - X25519 for encryption
  - Ed25519 for signing

### Example Code

```typescript
const alice = generateAuthenticatedKeySet();
const bob = generateAuthenticatedKeySet();

// Alice sends to Bob
const encrypted = await encrypt(
  {
    type: "authenticated-channel",
    recipientPublicKey: bob.encryption.publicKey,
    senderPrivateKey: alice.signing.privateKey,
    includeTimestamp: true,
  },
  "Digitally signed message"
);

// Bob verifies and decrypts
const decrypted = await decrypt(
  {
    type: "authenticated-channel",
    recipientPrivateKey: bob.encryption.privateKey,
    senderPublicKey: alice.signing.publicKey,
    validateTimestamp: true,
  },
  encrypted.data
);

console.log("Authenticated:", decrypted.metadata.authenticated); // true
```

---

## 🎭 Real-World Scenarios

### Scenario 1: Personal Photo Backup

**Best Choice:** `symmetric-password`

- One user (you)
- No need to share with others
- Simple and fast

### Scenario 2: Sending Tax Documents to Accountant

**Best Choice:** `sealEnvelope` or `authenticated-channel`

- `sealEnvelope`: If just confidentiality needed
- `authenticated-channel`: If you need to prove you sent it (legal requirement)

### Scenario 3: Secure Messaging App

**Best Choice:** `secure-channel`

- Real-time communication
- Forward secrecy important (in case phone stolen)
- Many messages per day (performance matters)

### Scenario 4: Medical Records System

**Best Choice:** `authenticated-channel`

- HIPAA compliance requires audit trail
- Need to prove which doctor created/modified record
- Legal requirement for non-repudiation

### Scenario 5: Password Manager

**Best Choice:** `symmetric-password`

- Local only (not sending to anyone)
- Master password model
- Maximum performance for frequent access

### Scenario 6: Corporate Email Encryption

**Best Choice:** `sealEnvelope` (if legacy compatibility needed) or `secure-channel`

- `sealEnvelope`: Compatible with S/MIME, PGP standards
- `secure-channel`: Modern, better security properties

---

## 📈 Performance Comparison

Benchmarked on: Intel i7, Node.js 20.x

| Mode                  | Small Message (1 KB) | Large File (100 MB) | Keys per Operation |
| --------------------- | -------------------- | ------------------- | ------------------ |
| symmetric-password    | ~0.5 ms              | ~2.1 seconds        | 0 (password only)  |
| sealEnvelope          | ~8.2 ms              | ~2.5 seconds        | 1 public key       |
| secure-channel        | ~1.2 ms              | ~2.1 seconds        | 1 public key       |
| authenticated-channel | ~1.8 ms              | ~2.2 seconds        | 2 public keys      |

**Note:** File encryption uses streaming, so large files have minimal memory overhead.

---

## 🔄 Migration Paths

### From symmetric-password to secure-channel

```typescript
// Old: password-based
await encrypt({ type: "symmetric-password", password: "secret" }, data);

// New: generate keys once
const keys = generateX25519KeyPair();
// Share keys.publicKey with others

// Then use secure-channel
await encrypt(
  { type: "secure-channel", recipientPublicKey: keys.publicKey },
  data
);
```

### From sealEnvelope to authenticated-channel

```typescript
// Old: RSA only
const rsa = generateRSAKeyPair();
await encrypt(
  { type: "sealEnvelope", recipientPublicKey: rsa.publicKey },
  data
);

// New: Generate both key types
const keySet = generateAuthenticatedKeySet();
// keySet.encryption (X25519) replaces RSA
// keySet.signing (Ed25519) is new

await encrypt(
  {
    type: "authenticated-channel",
    recipientPublicKey: keySet.encryption.publicKey,
    senderPrivateKey: myKeySet.signing.privateKey,
  },
  data
);
```

---

## 💡 Best Practices Summary

1. **Start simple**: Use `symmetric-password` for personal projects
2. **Add complexity when needed**: Move to public-key modes when sharing with others
3. **Use forward secrecy**: Prefer `secure-channel` over `sealEnvelope` for modern apps
4. **Add authentication for critical data**: Use `authenticated-channel` for high-value transactions
5. **Enable strict mode**: Always use `strictMode: true` for production
6. **Validate timestamps**: Keep replay protection enabled (default)
7. **Rotate keys regularly**: Especially for long-running systems

---

## 🆘 Still Not Sure?

Ask yourself:

1. **Who decrypts?**

   - Just me → `symmetric-password`
   - Someone else → Public-key mode

2. **Need to prove sender?**

   - No → `sealEnvelope` or `secure-channel`
   - Yes → `authenticated-channel`

3. **Worried about key compromise?**

   - Not really → `sealEnvelope`
   - Yes → `secure-channel` or `authenticated-channel`

4. **What's at stake?**
   - Low (personal) → Simpler modes OK
   - High (financial/medical) → Use `authenticated-channel`

When in doubt, use **`secure-channel`** - it provides good security properties with reasonable complexity.
