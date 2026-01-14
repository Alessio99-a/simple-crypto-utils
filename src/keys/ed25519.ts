import { generateKeyPairSync } from "crypto";

/**
 * Generates an Ed25519 key pair for digital signatures.
 *
 * The keys are generated using the Ed25519 algorithm and exported as:
 * - Public key: SPKI (DER), Base64-encoded
 * - Private key: PKCS#8 (DER), Base64-encoded
 *
 * These keys are suitable for signing and verifying messages
 * in authenticated and secure communication protocols.
 *
 * @returns An object containing:
 *  - `publicKey`: Base64-encoded Ed25519 public key (DER, SPKI)
 *  - `privateKey`: Base64-encoded Ed25519 private key (DER, PKCS#8)
 *
 * @example
 * ```ts
 * import { generateEd25519KeyPair } from "./ed25519";
 *
 * const { publicKey, privateKey } = generateEd25519KeyPair();
 *
 * console.log(publicKey);  // Share publicly
 * console.log(privateKey); // Keep secret
 * ```
 */
export function generateEd25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
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
