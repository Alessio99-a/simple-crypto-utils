import {
  randomBytes,
  scryptSync,
  createCipheriv,
  createDecipheriv,
} from "crypto";

// Encrypt
export function encrypt(text: string, password: string) {
  const salt = randomBytes(16); // random salt
  const key = scryptSync(password, salt, 32); // derive 32-byte key
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  // Return everything needed to decrypt
  return Buffer.concat([salt, iv, tag, encrypted]).toString("hex");
}
