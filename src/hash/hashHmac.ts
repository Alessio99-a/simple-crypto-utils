import { createHmac } from "crypto";

/**
 * Computes a SHA-256 HMAC for a given string using a secret key.
 *
 * HMAC (Hash-based Message Authentication Code) ensures both
 * data integrity and authenticity.
 *
 * @param secret - The secret key used to compute the HMAC.
 * @param data - The input string to hash.
 * @returns The HMAC as a hexadecimal string.
 *
 * @example
 * ```ts
 * import { hashHmac } from "./hmac";
 *
 * const secret = "mysecretkey";
 * const message = "Hello, world!";
 * const hmac = hashHmac(secret, message);
 *
 * console.log(hmac); // e.g., "a6f5c3b2e4d1..."
 * ```
 */
export function hashHmac(secret: string, data: string): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}
