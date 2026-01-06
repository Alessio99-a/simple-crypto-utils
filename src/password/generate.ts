import { randomBytes } from "crypto";
import { hashPassword } from "./hash";

interface PasswordOptions {
  length?: number;
  hash?: boolean;
  letters?: boolean;
  numbers?: boolean;
  symbols?: boolean;
}

const charsetMap: Readonly<Record<string, string>> = {
  letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

// Conditional return type
export function generatePassword(length?: number): string;
export function generatePassword(
  options: PasswordOptions & { hash?: false }
): string;
export function generatePassword(
  options: PasswordOptions & { hash: true }
): Promise<string>;

// Implementation
export function generatePassword(
  lengthOrOptions?: number | PasswordOptions
): string | Promise<string> {
  let length = 16;
  let hash = false;
  let letters = true;
  let numbers = true;
  let symbols = true;

  if (typeof lengthOrOptions === "number") {
    length = lengthOrOptions;
  } else if (typeof lengthOrOptions === "object") {
    length = lengthOrOptions.length ?? 16;
    hash = lengthOrOptions.hash ?? false;
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

  if (hash) {
    // Return a Promise only if hash is true
    return hashPassword(password);
  }

  return password;
}
