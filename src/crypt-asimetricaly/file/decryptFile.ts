import { createReadStream, createWriteStream, readFileSync } from "fs";
import { createDecipheriv, privateDecrypt, constants } from "crypto";
import { pipeline } from "stream/promises";

interface FileHeader {
  encryptedKey: string;
  iv: string;
  authTag: string;
}

export async function decryptFile(
  inputPath: string,
  outputPath: string,
  privateKey: string
) {
  const fd = readFileSync(inputPath);

  const headerLength = fd.readUInt32BE(0);
  const headerJson = fd.slice(4, 4 + headerLength).toString("utf8");
  const header: FileHeader = JSON.parse(headerJson);

  const encryptedKeyBuf = Buffer.from(header.encryptedKey, "base64");
  const iv = Buffer.from(header.iv, "base64");
  const authTag = Buffer.from(header.authTag, "base64");

  const aesKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKeyBuf
  );

  const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);

  const inputStream = createReadStream(inputPath, {
    start: 4 + headerLength,
  });
  const outputStream = createWriteStream(outputPath);

  await pipeline(inputStream, decipher, outputStream);
}
