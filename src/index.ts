/**
 * Secure Crypto Library - Main Export File
 *
 * A comprehensive educational cryptography library implementing:
 * - Symmetric encryption (AES-256-GCM with password)
 * - Asymmetric encryption (RSA-OAEP)
 * - ECDH key exchange (X25519)
 * - Digital signatures (Ed25519)
 * - Forward secrecy
 * - Replay attack prevention
 *
 * @module secure-crypto-library
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
// Key Generation Utilities
// ============================================

export {
  generateRSAKeyPair,
  generateX25519KeyPair,
  generateEd25519KeyPair,
  generateAuthenticatedKeySet,
  isValidBase64,
  getKeyInfo,
} from "./utlis/utily";

// ============================================
// Type Definitions
// ============================================

/**
 * Options for symmetric password-based encryption
 */
export interface SymmetricPasswordOptions {
  type: "symmetric-password";
  password: string;
  stream?: boolean;
  strictMode?: boolean;
}

/**
 * Options for RSA envelope encryption
 */
export interface SealEnvelopeOptions {
  type: "sealEnvelope";
  recipientPublicKey: string;
  stream?: boolean;
  strictMode?: boolean;
}

/**
 * Options for ECDH secure channel
 */
export interface SecureChannelOptions {
  type: "secure-channel";
  recipientPublicKey: string;
  includeTimestamp?: boolean;
  stream?: boolean;
  strictMode?: boolean;
}

/**
 * Options for authenticated ECDH channel with signatures
 */
export interface AuthenticatedChannelOptions {
  type: "authenticated-channel";
  recipientPublicKey: string;
  senderPrivateKey: string;
  includeTimestamp?: boolean;
  stream?: boolean;
  strictMode?: boolean;
}

/**
 * Union type of all encryption options
 */
export type EncryptOptions =
  | SymmetricPasswordOptions
  | SealEnvelopeOptions
  | SecureChannelOptions
  | AuthenticatedChannelOptions;

/**
 * Options for decrypting symmetric password-based encryption
 */
export interface DecryptSymmetricOptions {
  type: "symmetric-password";
  password: string;
  strictMode?: boolean;
}

/**
 * Options for decrypting RSA envelope
 */
export interface DecryptEnvelopeOptions {
  type: "openEnvelope";
  recipientPrivateKey: string;
  strictMode?: boolean;
}

/**
 * Options for decrypting ECDH secure channel
 */
export interface DecryptSecureChannelOptions {
  type: "secure-channel";
  recipientPrivateKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

/**
 * Options for decrypting authenticated channel
 */
export interface DecryptAuthenticatedOptions {
  type: "authenticated-channel";
  recipientPrivateKey: string;
  senderPublicKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

/**
 * Union type of all decryption options
 */
export type DecryptOptions =
  | DecryptSymmetricOptions
  | DecryptEnvelopeOptions
  | DecryptSecureChannelOptions
  | DecryptAuthenticatedOptions;

/**
 * Result of encryption operation
 */
export interface EncryptResult {
  type: "file" | "message";
  data?: string;
  outputPath?: string;
}

/**
 * Result of decryption operation
 */
export interface DecryptResult {
  type: "file" | "message";
  data?: string | object;
  outputPath?: string;
  metadata?: {
    timestamp?: number;
    authenticated?: boolean;
  };
}

/**
 * Key pair structure
 */
export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Authenticated key set (encryption + signing keys)
 */
export interface AuthenticatedKeySet {
  encryption: KeyPair;
  signing: KeyPair;
}

// ============================================
// Constants
// ============================================

/**
 * Current format version
 */
export const LIBRARY_VERSION = VERSION;

/**
 * Minimum password length required
 */
export const MINIMUM_PASSWORD_LENGTH = MIN_PASSWORD_LENGTH;

/**
 * Maximum message age before rejection (replay protection)
 */
export const MAX_MESSAGE_AGE = MESSAGE_MAX_AGE_MS;

// ============================================
// Quick Start Examples
// ============================================

/**
 * @example
 * // Symmetric encryption
 * import { encrypt, decrypt } from 'secure-crypto-library';
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
 * import { encrypt, decrypt, generateRSAKeyPair } from 'secure-crypto-library';
 *
 * const keys = generateRSAKeyPair();
 *
 * const encrypted = await encrypt(
 *   { type: "sealEnvelope", recipientPublicKey: keys.publicKey },
 *   "Confidential data"
 * );
 *
 * const decrypted = await decrypt(
 *   { type: "openEnvelope", recipientPrivateKey: keys.privateKey },
 *   encrypted.data
 * );
 *
 * @example
 * // Secure channel with forward secrecy
 * import { encrypt, decrypt, generateX25519KeyPair } from 'secure-crypto-library';
 *
 * const bob = generateX25519KeyPair();
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
 * import { encrypt, decrypt, generateAuthenticatedKeySet } from 'secure-crypto-library';
 *
 * const alice = generateAuthenticatedKeySet();
 * const bob = generateAuthenticatedKeySet();
 *
 * const encrypted = await encrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPublicKey: bob.encryption.publicKey,
 *     senderPrivateKey: alice.signing.privateKey
 *   },
 *   "Signed message"
 * );
 *
 * const decrypted = await decrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPrivateKey: bob.encryption.privateKey,
 *     senderPublicKey: alice.signing.publicKey
 *   },
 *   encrypted.data
 * );
 */
