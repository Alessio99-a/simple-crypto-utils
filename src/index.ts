/**
 * Crypto Utils - Main Export File
 *
 * A comprehensive educational cryptography library implementing:
 * - Symmetric encryption (AES-256-GCM with password)
 * - Asymmetric encryption (RSA-OAEP)
 * - ECDH key exchange (X25519)
 * - Digital signatures (Ed25519)
 * - Forward secrecy
 * - Replay attack prevention
 *
 * @module crypto-utils
 * @version 1.0.0
 */

// ============================================
// Core Encryption/Decryption Functions
// ============================================

import {
  VERSION,
  MIN_PASSWORD_LENGTH,
  MESSAGE_MAX_AGE_MS,
} from "./crypto/encrypt";

// ============================================
// PASSWORD
// ============================================

/**
 * Password utilities for generating and validating secure passwords.
 *
 * Includes functions for:
 * - Generating cryptographically secure random passwords with customizable character sets
 * - Hashing passwords using scrypt with automatic salt generation
 * - Verifying passwords against stored hashes with timing-safe comparison
 *
 * @example
 * ```typescript
 * import { password } from 'simple-crypto-utils';
 *
 * // Generate a 20-character password
 * const pwd = password.generatePassword(20);
 *
 * // Generate with custom options
 * const numericOnly = password.generatePassword({
 *   length: 12,
 *   letters: false,
 *   symbols: false
 * });
 *
 * // Hash and verify
 * const hashed = await password.hashPassword("myPassword123");
 * const isValid = await password.verifyPassword("myPassword123", hashed);
 * ```
 */
export * as password from "./password";

// ============================================
// UUID
// ============================================

/**
 * UUID generation utilities using cryptographically secure random values.
 *
 * Generates RFC 4122 version 4 UUIDs suitable for use as unique identifiers
 * in databases, distributed systems, and APIs.
 *
 * @example
 * ```typescript
 * import { uuid } from 'simple-crypto-utils';
 *
 * const id = uuid.generateUUID();
 * console.log(id); // "3b241101-e2bb-4255-8caf-4136c566a962"
 * ```
 */
export * as uuid from "./uuid";

// ============================================
// SIGNATURE
// ============================================

/**
 * Digital signature utilities using Ed25519 elliptic curve cryptography.
 *
 * Provides functions for:
 * - Signing data with private keys
 * - Verifying signatures with public keys
 * - Creating signed envelopes (data + signature)
 * - Flexible serialization strategies (canonical, raw, selective)
 *
 * Ed25519 signatures are fast, secure, and produce small signatures (64 bytes).
 *
 * @example
 * ```typescript
 * import { signature, keys } from 'simple-crypto-utils';
 *
 * // Generate signing keys
 * const keyPair = await keys.Key.generate("sign");
 *
 * // Sign data
 * const data = { message: "Hello", timestamp: Date.now() };
 * const sig = signature.sign(data, keyPair.privateKey);
 *
 * // Verify signature
 * const isValid = signature.verify(data, sig, keyPair.publicKey);
 *
 * // Use envelope pattern
 * const envelope = signature.envelope(data, keyPair.privateKey);
 * const result = signature.openEnvelope(envelope, keyPair.publicKey);
 * ```
 */
export * as signature from "./signature";

// ============================================
// HASH
// ============================================

/**
 * Cryptographic hashing utilities using SHA-256.
 *
 * Provides functions for:
 * - Computing SHA-256 hashes of strings
 * - Creating HMAC (Hash-based Message Authentication Code) for data integrity
 * - Verifying HMACs with timing-safe comparison to prevent timing attacks
 *
 * Use hashing for:
 * - Data integrity verification
 * - Content fingerprinting
 * - Message authentication (with HMAC)
 *
 * @example
 * ```typescript
 * import { hash } from 'simple-crypto-utils';
 *
 * // Simple hash
 * const digest = hash.hash("Hello, world!");
 *
 * // HMAC for authenticated messages
 * const secret = "my-secret-key";
 * const message = "Important data";
 * const mac = hash.hashHmac(secret, message);
 *
 * // Verify HMAC (timing-safe)
 * const isValid = hash.verifyHmac(secret, message, mac);
 * ```
 */
export * as hash from "./hash";

// ============================================
// Key Generation
// ============================================

/**
 * Cryptographic key generation utilities for various algorithms.
 *
 * Supports generating key pairs for:
 * - **RSA-OAEP** (2048-bit): Asymmetric encryption and signing
 * - **X25519** (ECDH): Elliptic curve key exchange for secure channels
 * - **Ed25519**: Fast digital signatures
 * - **Authenticated channels**: Combined X25519 + Ed25519 key sets
 *
 * The `Key` class provides a unified interface for generating keys based on use case.
 *
 * @example
 * ```typescript
 * import { keys } from 'simple-crypto-utils';
 *
 * // Generate RSA keys for encryption
 * const rsaKeys = await keys.generateRSAKeyPair();
 *
 * // Generate X25519 keys for ECDH
 * const ecdhKeys = keys.generateECDHKeyPair();
 *
 * // Use the Key class for specific use cases
 * const sealKey = await keys.Key.generate("seal");
 * const signKey = await keys.Key.generate("sign");
 * const channelKey = await keys.Key.generate("secure-channel");
 * const authKey = await keys.Key.generate("authenticated-channel");
 * ```
 */
export * as keys from "./keys";

// ============================================
// OTP / TOTP
// ============================================

/**
 * One-Time Password (OTP) and Time-based OTP (TOTP) generation utilities.
 *
 * Provides functions for:
 * - Generating numeric OTPs of configurable length
 * - Generating TOTP codes compatible with RFC 6238 (Google Authenticator, Authy, etc.)
 * - Customizable time periods and digit counts for TOTP
 *
 * Use cases:
 * - Two-factor authentication (2FA)
 * - Multi-factor authentication (MFA)
 * - Email/SMS verification codes
 * - Session tokens
 *
 * @example
 * ```typescript
 * import { otp } from 'simple-crypto-utils';
 *
 * // Generate a 6-digit OTP
 * const code = otp.generateOTP();
 * console.log(code); // "084321"
 *
 * // Generate an 8-digit OTP
 * const longCode = otp.generateOTP(8);
 *
 * // Generate TOTP (compatible with Google Authenticator)
 * const secret = "JBSWY3DPEHPK3PXP"; // Base32-encoded secret
 * const totpCode = otp.generateTOTP(secret);
 * console.log(totpCode); // "492039"
 *
 * // Custom TOTP with 8 digits and 60-second period
 * const customTOTP = otp.generateTOTP(secret, 8, 60);
 * ```
 */
export * as otp from "./otp";

// ============================================
// Encryption/Decryption
// ============================================

export {
  encrypt,
  encryptMessage,
  encryptFileStreaming,
  deriveAESKeyForEncryption,
  VERSION,
  MIN_PASSWORD_LENGTH,
  MESSAGE_MAX_AGE_MS,
} from "./crypto/encrypt";

export {
  decrypt,
  decryptFile,
  decryptMessage,
  deriveAESKeyForDecryption,
  validateTimestamp,
  validateVersion,
} from "./crypto/decrypt";

// ============================================
// Validation Functions
// ============================================

export {
  validatePassword,
  validatePublicKey,
  validatePrivateKey,
} from "./crypto/encrypt";

// ============================================
// Type Definitions
// ============================================

export interface SymmetricPasswordOptions {
  type: "symmetric-password";
  password: string;
  stream?: boolean;
  strictMode?: boolean;
}

export interface SealEnvelopeOptions {
  type: "sealEnvelope";
  recipientPublicKey: string;
  stream?: boolean;
  strictMode?: boolean;
}

export interface SecureChannelOptions {
  type: "secure-channel";
  recipientPublicKey: string;
  includeTimestamp?: boolean;
  stream?: boolean;
  strictMode?: boolean;
}

export interface AuthenticatedChannelOptions {
  type: "authenticated-channel";
  recipientPublicKey: string;
  senderPrivateKey: string;
  includeTimestamp?: boolean;
  stream?: boolean;
  strictMode?: boolean;
}

export type EncryptOptions =
  | SymmetricPasswordOptions
  | SealEnvelopeOptions
  | SecureChannelOptions
  | AuthenticatedChannelOptions;

export interface DecryptSymmetricOptions {
  type: "symmetric-password";
  password: string;
  strictMode?: boolean;
}

export interface DecryptEnvelopeOptions {
  type: "openEnvelope";
  recipientPrivateKey: string;
  strictMode?: boolean;
}

export interface DecryptSecureChannelOptions {
  type: "secure-channel";
  recipientPrivateKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

export interface DecryptAuthenticatedOptions {
  type: "authenticated-channel";
  recipientPrivateKey: string;
  senderPublicKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

export type DecryptOptions =
  | DecryptSymmetricOptions
  | DecryptEnvelopeOptions
  | DecryptSecureChannelOptions
  | DecryptAuthenticatedOptions;

export interface EncryptResult {
  type: "file" | "message";
  data?: string;
  outputPath?: string;
}

export interface DecryptResult {
  type: "file" | "message";
  data?: string | object;
  outputPath?: string;
  metadata?: {
    timestamp?: number;
    authenticated?: boolean;
  };
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface AuthenticatedKeySet {
  encryption: KeyPair;
  signing: KeyPair;
}

// ============================================
// Constants
// ============================================

export const LIBRARY_VERSION = VERSION;
export const MINIMUM_PASSWORD_LENGTH = MIN_PASSWORD_LENGTH;
export const MAX_MESSAGE_AGE = MESSAGE_MAX_AGE_MS;

// ============================================
// Quick Start Examples
// ============================================

/**
 * @example
 * // Symmetric encryption
 * import { encrypt, decrypt } from 'simple-crypto-utils';
 *
 * const encrypted = await encrypt(
 *   { type: "symmetric-password", password: "MySecurePass123!" },
 *   "Secret message"
 * );
 *
 * const decrypted = await decrypt(
 *   { type: "symmetric-password", password: "MySecurePass123!" },
 *   encrypted.data
 * );
 *
 * @example
 * // RSA envelope encryption
 * import { encrypt, decrypt, keys } from 'simple-crypto-utils';
 *
 * const keyPair = await keys.generateRSAKeyPair();
 *
 * const encrypted = await encrypt(
 *   { type: "sealEnvelope", recipientPublicKey: keyPair.publicKey },
 *   "Confidential data"
 * );
 *
 * const decrypted = await decrypt(
 *   { type: "openEnvelope", recipientPrivateKey: keyPair.privateKey },
 *   encrypted.data
 * );
 *
 * @example
 * // Secure channel with forward secrecy
 * import { encrypt, decrypt, keys } from 'simple-crypto-utils';
 *
 * const bob = keys.generateECDHKeyPair();
 *
 * const encrypted = await encrypt(
 *   { type: "secure-channel", recipientPublicKey: bob.publicKey },
 *   "Private message"
 * );
 *
 * const decrypted = await decrypt(
 *   { type: "secure-channel", recipientPrivateKey: bob.privateKey },
 *   encrypted.data
 * );
 *
 * @example
 * // Authenticated channel with signatures
 * import { encrypt, decrypt, keys } from 'simple-crypto-utils';
 *
 * const alice = await keys.Key.generate("authenticated-channel");
 * const bob = await keys.Key.generate("authenticated-channel");
 *
 * const encrypted = await encrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPublicKey: bob.publicKey,
 *     senderPrivateKey: alice.signingPrivateKey
 *   },
 *   "Signed message"
 * );
 *
 * const decrypted = await decrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPrivateKey: bob.privateKey,
 *     senderPublicKey: alice.signingPublicKey
 *   },
 *   encrypted.data
 * );
 */
