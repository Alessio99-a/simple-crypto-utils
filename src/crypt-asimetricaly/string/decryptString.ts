// decryptString.ts
import { Buffer } from "buffer";
import { createDecipheriv, privateDecrypt, constants } from "crypto";

export function decryptString(
  encryptedData: string,
  encryptedKey: string,
  iv: string,
  authTag: string,
  privateKey: string
): string {
  // Decode from base64
  const encryptedDataBuf = Buffer.from(encryptedData, "base64");
  const encryptedKeyBuf = Buffer.from(encryptedKey, "base64"); // ✅ FIXED: removed .substring(0, 12)
  const ivBuf = Buffer.from(iv, "base64");
  const authTagBuf = Buffer.from(authTag, "base64");

  // Validate buffer sizes
  if (ivBuf.length !== 12) {
    throw new Error(
      `Invalid IV length: expected 12 bytes, got ${ivBuf.length}`
    );
  }
  if (authTagBuf.length !== 16) {
    throw new Error(
      `Invalid auth tag length: expected 16 bytes, got ${authTagBuf.length}`
    );
  }

  // Decrypt the AES key using RSA private key
  let aesKey: Buffer;
  try {
    aesKey = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedKeyBuf
    );
  } catch (e) {
    throw new Error(`Failed to decrypt AES key: ${e}`);
  }

  // Validate AES key length
  if (aesKey.length !== 32) {
    throw new Error(
      `Invalid AES key length: expected 32 bytes, got ${aesKey.length}`
    );
  }

  // Decrypt the data using AES-256-GCM
  const decipher = createDecipheriv("aes-256-gcm", aesKey, ivBuf);
  decipher.setAuthTag(authTagBuf);

  try {
    const decrypted = Buffer.concat([
      decipher.update(encryptedDataBuf),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch (e) {
    throw new Error(`Decryption failed (authentication error): ${e}`);
  }
}
