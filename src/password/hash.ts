import { randomBytes, scrypt as scryptCallback } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scryptCallback);

export async function hash(password: string): Promise<string> {
  const salt = randomBytes(16); // 16 bytes = 128 bits
  const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer;
  const saltBase64 = salt.toString("base64");
  const hashBase64 = derivedKey.toString("base64");

  // Format: scrypt$<saltLength>$<saltBase64>$<hashBase64>
  return `scrypt$16$${saltBase64}$${hashBase64}`;
}
