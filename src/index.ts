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
 * -
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
export * as password from "./password";

// ============================================
// UUID
// ============================================
export * as uuid from "./uuid";

// ============================================
// SIGNATURE
// ============================================
export * as signature from "./signature";

// ============================================
// HASH
// ============================================
export * as hash from "./hash";

// ============================================
// Key Generation
// ============================================
export * as keys from "./keys";

// ============================================
// OTP / TOTP
// ============================================
export * as otp from "./otp";

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
 * import { encrypt, decrypt } from 'crypto-utils';
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
 * import { encrypt, decrypt, generateRSAKeyPair } from 'crypto-utils';
 *
 * const keys = await generateRSAKeyPair();
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
 * import { encrypt, decrypt, generateX25519KeyPair } from 'crypto-utils';
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
 * import { encrypt, decrypt, generateAuthenticatedKeySet } from 'crypto-utils';
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
