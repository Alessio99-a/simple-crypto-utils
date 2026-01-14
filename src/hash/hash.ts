import { createHash } from "crypto";

/**
 * Computes the SHA-256 hash of a given string.
 *
 * @param data - The input string to hash.
 * @returns The SHA-256 hash of the input as a hexadecimal string.
 *
 * @example
 * ```ts
 * import { hash } from "./hash";
 *
 * const data = "Hello, world!";
 * const hashed = hash(data);
 *
 * console.log(hashed); // e.g., "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b247724e5b3f6d0f8c13f0"
 * ```
 */
export function hash(data: string): string {
  const hash = createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}
