// encryptString.ts
import { randomBytes, createCipheriv, publicEncrypt, constants } from "crypto";
import { generateAESKey } from "./generateAES";

export function encryptString(
  data: string,
  publicKey: string
): {
  encryptedData: string;
  encryptedKey: string;
  iv: string;
  authTag: string;
} {
  const { key, iv } = generateAESKey();

  // Encrypt the data with AES-256-GCM
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(data, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Encrypt the AES key with RSA public key
  const encryptedKey = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    key
  );

  return {
    encryptedData: encryptedBuffer.toString("base64"),
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
  };
}
