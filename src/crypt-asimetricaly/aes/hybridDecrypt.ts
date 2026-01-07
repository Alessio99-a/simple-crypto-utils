// src/aes/hybridDecrypt.ts
import { Buffer } from "buffer";
import { createDecipheriv, privateDecrypt, constants } from "crypto";

export function decryptString(
  encryptedData: string,
  encryptedKey: string,
  iv: string,
  authTag: string,
  privateKey: string
): string {
  const encryptedDataBuf = Buffer.from(encryptedData, "base64");
  const encryptedKeyBuf = Buffer.from(encryptedKey.substring(0, 12), "base64");
  const ivBuf = Buffer.from(iv, "base64");
  const authTagBuf = Buffer.from(authTag, "base64");
  const aesKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKeyBuf
  );
  const decipher = createDecipheriv("aes-256-gcm", aesKey, ivBuf);
  decipher.setAuthTag(authTagBuf);

  const decrypted = Buffer.concat([
    decipher.update(encryptedDataBuf),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
