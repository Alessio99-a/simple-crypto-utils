import {
  createReadStream,
  createWriteStream,
  readFileSync,
  writeFileSync,
  statSync,
} from "fs";
import { createCipheriv, publicEncrypt, randomBytes, constants } from "crypto";
import { pipeline } from "stream/promises";
import { tmpdir } from "os";
import { join } from "path";
import { open } from "fs/promises";

interface FileHeader {
  encryptedKey: string; // base64
  iv: string; // base64
  authTag: string; // base64
}

// Memory-efficient version for large files
export async function encryptFile(
  inputPath: string,
  outputPath: string,
  publicKey: string
) {
  const LARGE_FILE_THRESHOLD = 100 * 1024 * 1024; // 100 MB
  const fileSize = statSync(inputPath).size;

  if (fileSize > LARGE_FILE_THRESHOLD) {
    console.log(
      `Large file detected (${(fileSize / 1024 / 1024).toFixed(
        2
      )} MB), using streaming...`
    );
    return encryptFileStreaming(inputPath, outputPath, publicKey);
  } else {
    return encryptFileSmall(inputPath, outputPath, publicKey);
  }
}

// Streaming version - never loads full file into memory
async function encryptFileStreaming(
  inputPath: string,
  outputPath: string,
  publicKey: string
) {
  // 1️⃣ Generate AES key + IV
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  // 2️⃣ Encrypt AES key with RSA
  const encryptedKeyBuf = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  // 3️⃣ Encrypt to temporary file
  const tempPath = join(tmpdir(), `temp-encrypt-${Date.now()}.tmp`);
  const tempStream = createWriteStream(tempPath);
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const inputStream = createReadStream(inputPath);

  await pipeline(inputStream, cipher, tempStream);

  // 4️⃣ Get authTag
  const authTag = cipher.getAuthTag();

  // 5️⃣ Create header
  const header: FileHeader = {
    encryptedKey: encryptedKeyBuf.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
  };

  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerLengthBuf = Buffer.alloc(4);
  headerLengthBuf.writeUInt32BE(headerJson.length, 0);

  // 6️⃣ Stream temp file to final output (memory-efficient)
  const outputStream = createWriteStream(outputPath);

  // Write header first
  outputStream.write(headerLengthBuf);
  outputStream.write(headerJson);

  // Stream encrypted data
  const tempReadStream = createReadStream(tempPath);
  await pipeline(tempReadStream, outputStream);

  // 7️⃣ Clean up temp file
  try {
    const { unlinkSync } = await import("fs");
    unlinkSync(tempPath);
  } catch (e) {
    console.warn("Could not delete temp file:", tempPath);
  }

  console.log("✅ File encrypted successfully (streaming mode)");
  console.log("Header length:", headerJson.length);
}

// Original version - good for files < 100 MB
export async function encryptFileSmall(
  inputPath: string,
  outputPath: string,
  publicKey: string
) {
  // 1️⃣ Generate AES key + IV
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  // 2️⃣ Encrypt AES key with RSA
  const encryptedKeyBuf = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  // 3️⃣ Encrypt to temporary file first to get authTag
  const tempPath = join(tmpdir(), `temp-encrypt-${Date.now()}.tmp`);
  const tempStream = createWriteStream(tempPath);

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const inputStream = createReadStream(inputPath);

  await pipeline(inputStream, cipher, tempStream);

  // 4️⃣ Get authTag after encryption is complete
  const authTag = cipher.getAuthTag();

  // 5️⃣ Now create the final header with the real authTag
  const header: FileHeader = {
    encryptedKey: encryptedKeyBuf.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
  };

  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerLengthBuf = Buffer.alloc(4);
  headerLengthBuf.writeUInt32BE(headerJson.length, 0);

  // 6️⃣ Read the encrypted data from temp file
  const encryptedData = readFileSync(tempPath);

  // 7️⃣ Write final file: header length + header + encrypted data
  const finalData = Buffer.concat([headerLengthBuf, headerJson, encryptedData]);
  writeFileSync(outputPath, finalData);

  // 8️⃣ Clean up temp file
  try {
    const { unlinkSync } = await import("fs");
    unlinkSync(tempPath);
  } catch (e) {
    console.warn("Could not delete temp file:", tempPath);
  }

  console.log("✅ File encrypted successfully");
  console.log("Header length:", headerJson.length);
  console.log("Auth tag:", authTag.toString("base64"));
}
