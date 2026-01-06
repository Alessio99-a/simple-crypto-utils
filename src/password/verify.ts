import { randomBytes, scrypt as scryptCallback } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scryptCallback);

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

export async function verifyPassword(
  password: string,
  storedHash: string
): Promise<boolean> {
  const [method, saltLengthStr, saltBase64, hashBase64] = storedHash.split("$");
  console.log([method, saltLengthStr, saltBase64, hashBase64]);
  if (method !== "scrypt") throw new Error("Unsupported hash method");
  if (!saltBase64 || !hashBase64) throw new Error("Invalid stored hash format");

  const salt = Buffer.from(saltBase64, "base64");
  const derivedKey = await scryptTyped(password, salt, 64);
  const hashBuffer = Buffer.from(hashBase64, "base64");

  // Add explicit type assertions to satisfy TypeScript
  if (!derivedKey || !hashBuffer) {
    throw new Error("Buffer creation failed");
  }

  // Constant-time comparison
  if (derivedKey.length !== hashBuffer.length) return false;
  let diff = 0;
  for (let i = 0; i < derivedKey.length; i++) {
    diff |= derivedKey[i]! ^ hashBuffer[i]!;
  }
  return diff === 0;
}
