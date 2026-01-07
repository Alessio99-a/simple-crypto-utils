import { randomBytes } from "crypto";

export function generateAESKey(): { key: Buffer; iv: Buffer } {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  return { key, iv };
}
