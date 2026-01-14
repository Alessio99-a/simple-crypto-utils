import { randomBytes } from "crypto";

export interface PasswordOptions {
  /** Length of the password (default: 16) */
  length?: number;

  /** Include letters in the password (default: true) */
  letters?: boolean;

  /** Include numbers in the password (default: true) */
  numbers?: boolean;

  /** Include symbols in the password (default: true) */
  symbols?: boolean;
}

const charsetMap: Readonly<Record<string, string>> = {
  letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

// Conditional return type
export function generatePassword(length?: number): string;
export function generatePassword(options: PasswordOptions): string;
export function generatePassword(
  options: PasswordOptions & { hash: true }
): Promise<string>;

/**
 * Generates a secure random password.
 *
 * The password can include letters, numbers, and symbols. The length
 * must be between 1 and 1024. Optionally, the password could be hashed
 * (if `hash: true`), but hashing is currently commented out.
 *
 * @param lengthOrOptions - Either the length of the password or an options object.
 * @returns A randomly generated password as a string.
 *
 * @example
 * ```ts
 * import { generatePassword } from "./password";
 *
 * // Generate a default password of length 16
 * const pw1 = generatePassword();
 * console.log(pw1);
 *
 * // Generate a password of length 32 with only letters and numbers
 * const pw2 = generatePassword({ length: 32, symbols: false });
 * console.log(pw2);
 *
 * // Generate a password of length 12 using the numeric charset only
 * const pw3 = generatePassword({ length: 12, letters: false, symbols: false });
 * console.log(pw3);
 * ```
 */
export function generatePassword(
  lengthOrOptions?: number | PasswordOptions
): string | Promise<string> {
  let length = 16;
  let letters = true;
  let numbers = true;
  let symbols = true;

  if (typeof lengthOrOptions === "number") {
    length = lengthOrOptions;
  } else if (typeof lengthOrOptions === "object") {
    length = lengthOrOptions.length ?? 16;
    letters = lengthOrOptions.letters ?? true;
    numbers = lengthOrOptions.numbers ?? true;
    symbols = lengthOrOptions.symbols ?? true;
  }

  let charset = "";
  if (letters) charset += charsetMap.letters;
  if (numbers) charset += charsetMap.numbers;
  if (symbols) charset += charsetMap.symbols;

  if (charset.length === 0) {
    charset = Object.values(charsetMap).join("");
  }

  if (length < 1 || length > 1024) {
    throw new Error("Length must be between 1 and 1024");
  }

  const bytes = randomBytes(length);
  const password = Array.from(
    bytes,
    (byte) => charset[byte % charset.length]
  ).join("");

  return password;
}
