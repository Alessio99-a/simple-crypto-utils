import { generateKeyPairSync } from "crypto";

/**
 * Generates an X25519 key pair for Elliptic Curve Diffie-Hellman (ECDH).
 *
 * The keys are exported in DER format and encoded as Base64 strings:
 * - Public key: SPKI (SubjectPublicKeyInfo)
 * - Private key: PKCS#8
 *
 * This key pair is suitable for secure key agreement protocols.
 *
 * @returns An object containing:
 *  - `publicKey`: Base64-encoded X25519 public key (DER, SPKI)
 *  - `privateKey`: Base64-encoded X25519 private key (DER, PKCS#8)
 *
 * @example
 * ```ts
 * import { generateECDHKeyPair } from "./ecdh";
 *
 * const { publicKey, privateKey } = generateECDHKeyPair();
 *
 * console.log(publicKey);  // Send to the peer
 * console.log(privateKey); // Keep secret
 * ```
 */
export function generateECDHKeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");

  return {
    publicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    privateKey: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
  };
}
