import { scrypt as scryptCallback } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scryptCallback);

/**
 * Derives a key using scrypt and ensures a typed Buffer is returned.
 *
 * @param password - The password to derive the key from.
 * @param salt - The salt to use for key derivation.
 * @param keylen - The length of the derived key in bytes.
 * @returns A Promise resolving to the derived key as a Buffer.
 * @throws If scrypt fails or returns undefined.
 */
async function scryptTyped(
  password: string,
  salt: Buffer,
  keylen: number
): Promise<Buffer> {
  const result = (await scryptAsync(password, salt, keylen)) as
    | Buffer
    | undefined;
  if (!result) throw new Error("Scrypt derivation failed");
  return result;
}

/**
 * Validates a password against a stored scrypt hash.
 *
 * The stored hash must be in the format:
 * ```
 * scrypt$<saltLength>$<saltBase64>$<hashBase64>
 * ```
 * The function uses a constant-time comparison to prevent timing attacks.
 *
 * @param password - The password to verify.
 * @param storedHash - The stored hash string to validate against.
 * @returns `true` if the password matches the hash, `false` otherwise.
 *
 * @example
 * ```ts
 * import { hash } from "./password";
 * import { verifyPassword } from "./validate";
 *
 * async function main() {
 *   const password = "mySecretPassword";
 *   const hashed = await hash(password);
 *
 *   const isValid = await verifyPassword("mySecretPassword", hashed);
 *   console.log(isValid); // true
 *
 *   const isInvalid = await verifyPassword("wrongPassword", hashed);
 *   console.log(isInvalid); // false
 * }
 *
 * main();
 * ```
 */
export async function verifyPassword(
  password: string,
  storedHash: string
): Promise<boolean> {
  const [method, saltLengthStr, saltBase64, hashBase64] = storedHash.split("$");

  if (method !== "scrypt") throw new Error("Unsupported hash method");
  if (!saltBase64 || !hashBase64 || !saltLengthStr)
    throw new Error("Invalid stored hash format");

  const salt = Buffer.from(saltBase64, "base64");
  const derivedKey = await scryptTyped(password, salt, 64);
  const hashBuffer = Buffer.from(hashBase64, "base64");

  // Constant-time comparison
  if (derivedKey.length !== hashBuffer.length) return false;
  let diff = 0;
  for (let i = 0; i < derivedKey.length; i++) {
    diff |= derivedKey[i]! ^ hashBuffer[i]!;
  }
  return diff === 0;
}
