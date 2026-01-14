import { generateKeyPair } from "crypto";

/**
 * Generates an RSA key pair for encryption or digital signatures.
 *
 * - Algorithm: RSA
 * - Key size: 2048 bits
 * - Public key: SPKI (DER, base64-encoded)
 * - Private key: PKCS#8 (DER, base64-encoded)
 *
 * @returns A Promise that resolves to an object containing:
 *  - `publicKey`: RSA public key in base64-encoded DER format
 *  - `privateKey`: RSA private key in base64-encoded DER format
 *
 * @example
 * ```ts
 * import { generateRSAKeyPair } from "./rsa";
 *
 * async function main() {
 *   const { publicKey, privateKey } = await generateRSAKeyPair();
 *
 *   console.log(publicKey);  // Can be shared (base64 string)
 *   console.log(privateKey); // Keep secret (base64 string)
 * }
 *
 * main();
 * ```
 */
export function generateRSAKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      "rsa",
      {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "spki",
          format: "der", // Changed from "pem" to "der"
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "der", // Changed from "pem" to "der"
        },
      },
      (err, publicKey, privateKey) => {
        if (err) return reject(err);
        resolve({
          publicKey: publicKey.toString("base64"),
          privateKey: privateKey.toString("base64"),
        });
      }
    );
  });
}
