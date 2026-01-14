import { createHmac, timingSafeEqual } from "crypto";

/**
 * Verifies a SHA-256 HMAC for a given string using a secret key.
 *
 * This function uses a **timing-safe comparison** to prevent
 * timing attacks when comparing the expected HMAC to the actual one.
 *
 * @param secret - The secret key used to compute the HMAC.
 * @param data - The input string to hash.
 * @param expectedHex - The expected HMAC in hexadecimal format.
 * @returns `true` if the computed HMAC matches the expected one, `false` otherwise.
 *
 * @example
 * ```ts
 * import { hashHmac, verifyHmac } from "./hmac";
 *
 * const secret = "mysecretkey";
 * const message = "Hello, world!";
 *
 * const hmac = hashHmac(secret, message);
 * const isValid = verifyHmac(secret, message, hmac);
 *
 * console.log(isValid); // true
 * ```
 */
export function verifyHmac(
  secret: string,
  data: string,
  expectedHex: string
): boolean {
  const actual = createHmac("sha256", secret).update(data).digest();

  const expected = Buffer.from(expectedHex, "hex");

  if (actual.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(actual, expected);
}
