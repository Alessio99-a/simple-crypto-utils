import { generateKeyPairSync } from "crypto";

/**
 * Generates an X25519 key pair for Elliptic Curve Diffie-Hellman (ECDH).
 *
 * The keys are generated using the X25519 curve and exported as:
 * - Public key: SPKI (DER), Base64-encoded
 * - Private key: PKCS#8 (DER), Base64-encoded
 *
 * These keys are suitable for secure key exchange and shared secret derivation.
 *
 * @returns An object containing:
 *  - `publicKey`: Base64-encoded X25519 public key (DER, SPKI)
 *  - `privateKey`: Base64-encoded X25519 private key (DER, PKCS#8)
 *
 * @example
 * ```ts
 * import { generateX25519KeyPair } from "./x25519";
 *
 * const { publicKey, privateKey } = generateX25519KeyPair();
 *
 * console.log(publicKey);  // Share with peer
 * console.log(privateKey); // Keep secret
 * ```
 */
export function generateX25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  };
}
