import { randomBytes } from "crypto";

/**
 * Generates a random AES-256 key and initialization vector (IV).
 *
 * - The key is 32 bytes (256 bits), suitable for AES-256.
 * - The IV is 12 bytes, commonly used for AES-GCM.
 *
 * @returns An object containing:
 *  - `key`: A 32-byte Buffer representing the AES key.
 *  - `iv`: A 12-byte Buffer representing the initialization vector.
 *
 * @example
 * ```ts
 * import { generateAESKey } from "./crypto";
 *
 * const { key, iv } = generateAESKey();
 *
 * console.log(key.toString("hex")); // AES-256 key
 * console.log(iv.toString("hex"));  // Initialization vector
 * ```
 */
export function generateAESKey(): { key: Buffer; iv: Buffer } {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  return { key, iv };
}
