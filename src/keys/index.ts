import { generateRSAKeyPair } from "./rsa";
import { generateEd25519KeyPair } from "./ed25519";
import { generateX25519KeyPair } from "./x25519";
import { generateAuthenticatedKeySet } from "./authenticated";
export type keyType =
  | "seal"
  | "sign"
  | "secure-channel"
  | "authenticated-channel";

/**
 * Represents a cryptographic key or key pair for various use cases.
 *
 * Depending on the `keyType`, the instance may contain:
 * - Encryption keys (`publicKey` / `privateKey`)
 * - Signing keys (`signingPublicKey` / `signingPrivateKey`)
 */
export class Key {
  /** Public key for encryption or signing (Base64 or PEM depending on type) */
  publicKey?: string;

  /** Private key for encryption or signing (Base64 or PEM depending on type) */
  privateKey?: string;

  /** Public key specifically for signing (Base64) */
  signingPublicKey?: string;

  /** Private key specifically for signing (Base64) */
  signingPrivateKey?: string;

  /**
   * Generates a new Key instance for the specified `keyType`.
   *
   * @param key - The type of key to generate:
   *   - `"seal"`: RSA key pair for encryption/signing
   *   - `"sign"`: Ed25519 key pair for signing
   *   - `"secure-channel"`: X25519 key pair for ECDH (secure channel)
   *   - `"authenticated-channel"`: Combined X25519 + Ed25519 key pair
   *
   * @returns A Promise that resolves to a `Key` instance with the generated keys.
   *
   * @example
   * ```ts
   * import { Key } from "./key";
   *
   * async function main() {
   *   const sealKey = await Key.generate("seal");
   *   console.log(sealKey.publicKey);
   *   console.log(sealKey.privateKey);
   *
   *   const authKey = await Key.generate("authenticated-channel");
   *   console.log(authKey.publicKey);        // Encryption key
   *   console.log(authKey.signingPublicKey); // Signing key
   * }
   *
   * main();
   * ```
   */
  static async generate(key: keyType): Promise<Key> {
    const k = new Key(); // create instance inside
    switch (key) {
      case "authenticated-channel": {
        const key = generateAuthenticatedKeySet();
        k.publicKey = key.encryption.publicKey; // X25519 encryption public
        k.privateKey = key.encryption.privateKey; // X25519 encryption private (for decryption)
        k.signingPublicKey = key.signing.publicKey; // Ed25519 signing public
        k.signingPrivateKey = key.signing.privateKey; // Ed25519 signing private
        break;
      }
      case "secure-channel": {
        const { publicKey, privateKey } = generateX25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }
      case "seal": {
        const { publicKey, privateKey } = await generateRSAKeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }

      case "sign": {
        const { publicKey, privateKey } = generateEd25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }

      default:
        throw new Error(`Unknown key type: ${key}`);
    }
    return k; // return the new instance
  }
}

export { generateECDHKeyPair } from "./ecdh";
export { generateRSAKeyPair } from "./rsa";
