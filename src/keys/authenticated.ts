import { generateX25519KeyPair } from "./x25519";
import { generateEd25519KeyPair } from "./ed25519";

/**
 * Generates an authenticated key set composed of:
 *
 * - An X25519 key pair for encryption / key agreement
 * - An Ed25519 key pair for digital signatures
 *
 * This key set can be used in secure protocols that require
 * both confidentiality and authentication.
 *
 * @returns An object containing:
 *  - `encryption`: X25519 public/private key pair
 *  - `signing`: Ed25519 public/private key pair
 *
 * @example
 * ```ts
 * import { generateAuthenticatedKeySet } from "./keys";
 *
 * const keySet = generateAuthenticatedKeySet();
 *
 * // Encryption keys (X25519)
 * console.log(keySet.encryption.publicKey);
 * console.log(keySet.encryption.privateKey);
 *
 * // Signing keys (Ed25519)
 * console.log(keySet.signing.publicKey);
 * console.log(keySet.signing.privateKey);
 * ```
 */
export function generateAuthenticatedKeySet(): {
  encryption: { publicKey: string; privateKey: string };
  signing: { publicKey: string; privateKey: string };
} {
  return {
    encryption: generateX25519KeyPair(),
    signing: generateEd25519KeyPair(),
  };
}
