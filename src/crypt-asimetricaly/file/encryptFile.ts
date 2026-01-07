import {
  createReadStream,
  createWriteStream,
  write,
  readFileSync,
  close,
} from "fs";
import { createCipheriv, publicEncrypt, randomBytes, constants } from "crypto";
import { pipeline } from "stream/promises";
import { open } from "fs/promises";
interface FileHeader {
  encryptedKey: string;
  iv: string;
  authTag: string;
}

export async function encryptFile(
  inputPath: string,
  outputPath: string,
  publicKey: string
) {
  // 1️⃣ Generate AES key + IV
  const aesKey = randomBytes(32); // AES-256
  const iv = randomBytes(12); // GCM recommended

  // 2️⃣ Encrypt AES key with RSA
  const encryptedKey = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  // 3️⃣ Create AES cipher
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);

  // 4️⃣ Create header with placeholder authTag
  const header: FileHeader = {
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    authTag: "", // will fill later
  };
  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerLengthBuf = Buffer.alloc(4);
  headerLengthBuf.writeUInt32BE(headerJson.length, 0);

  // 5️⃣ Write header placeholder to file
  const outputStream = createWriteStream(outputPath);
  outputStream.write(headerLengthBuf);
  outputStream.write(headerJson);

  // 6️⃣ Stream input file → cipher → output
  const inputStream = createReadStream(inputPath);
  await pipeline(inputStream, cipher, outputStream);

  // 7️⃣ Get the authTag after streaming
  const authTag = cipher.getAuthTag().toString("base64");
  header.authTag = authTag;

  // 8️⃣ Rewrite header with real authTag
  const finalHeaderJson = Buffer.from(JSON.stringify(header), "utf8");
  if (finalHeaderJson.length !== headerJson.length) {
    throw new Error(
      "Header length changed after adding authTag — you need fixed-length header buffer"
    );
  }

  const fd = await open(outputPath, "r+");
  await fd.write(finalHeaderJson, 0, finalHeaderJson.length, 4);
  await fd.close();
}
