import { randomBytes, scrypt as scryptCallback } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scryptCallback);

/**
 * Generates a secure scrypt hash of a password.
 *
 * The hash is salted with 16 random bytes and the result is encoded in Base64.
 * The output format is:
 * ```
 * scrypt$16$<saltBase64>$<hashBase64>
 * ```
 *
 * @param password - The password to hash.
 * @returns A Promise resolving to the hashed password string.
 *
 * @example
 * ```ts
 * import { hashPassword } from "./password";
 *
 * async function main() {
 *   const hashed = await hashPassword("mySecretPassword");
 *   console.log(hashed);
 *   // Example output:
 *   // scrypt$16$3q2+7w==$pX9n0V5gK2v7r6Y3h8Zs2I3cL0y7hGqL8v9pN7l0K5Q=
 * }
 *
 * main();
 * ```
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16); // 16 bytes = 128 bits
  const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer;
  const saltBase64 = salt.toString("base64");
  const hashBase64 = derivedKey.toString("base64");

  // Format: scrypt$<saltLength>$<saltBase64>$<hashBase64>
  return `scrypt$16$${saltBase64}$${hashBase64}`;
}
