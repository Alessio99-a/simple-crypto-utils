import {
  randomBytes,
  createDecipheriv,
  publicEncrypt,
  createCipheriv,
  constants,
} from "crypto";
import { generateAESKey } from "./generateAES";

export function encryptString(
  data: string,
  publickKey: string
): {
  encryptedData: string;
  encryptedKey: string;
  iv: string;
  authTag: string;
} {
  const { key, iv } = generateAESKey();

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(data, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const encryptedKey = publicEncrypt(
    {
      key: publickKey,
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
