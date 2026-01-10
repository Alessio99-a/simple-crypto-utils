// ============================================
// DECRYPT.TS - Complete and Corrected
// ============================================

import * as Stream from "stream";
import { createReadStream, createWriteStream } from "fs";
import {
  createDecipheriv,
  privateDecrypt,
  constants,
  scryptSync,
  createECDH,
  hkdfSync,
} from "crypto";
import { pipeline } from "stream/promises";

interface FileHeader {
  encryptedKey?: string; // base64 - for RSA modes
  ephemeralPublicKey?: string; // base64 - for ECDH mode
  iv: string; // base64
  authTag: string; // base64
  salt?: string; // base64 - for password mode AND ECDH mode
}

type DecryptOptions =
  | { type: "symmetric-password"; password: string }
  | { type: "openEnvelope"; recipientPrivateKey: string }
  | {
      type: "secure-channel";
      recipientPrivateKey: string;
      // ❌ REMOVED: senderPublicKey - not needed, ephemeral key comes from message
    };

interface DecryptResult {
  type: "file" | "message";
  data?: string | object;
  outputPath?: string;
}

/**
 * Main decryption function - handles both messages and files
 */
async function decrypt(
  options: DecryptOptions,
  data: string | Buffer,
  inputPath?: string,
  outputPath?: string
): Promise<DecryptResult> {
  if (!data) {
    throw new Error("No data to decrypt");
  }

  const isFile = inputPath && outputPath;

  if (isFile) {
    await decryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    const encryptedHex = typeof data === "string" ? data : data.toString("hex");
    const decrypted = decryptMessage(options, encryptedHex);
    return { type: "message", data: decrypted };
  }
}

/**
 * Decrypt a file
 */
async function decryptFile(
  options: DecryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  async function readFileHeader(
    filePath: string
  ): Promise<{ header: FileHeader; encryptedDataOffset: number }> {
    return new Promise((resolve, reject) => {
      const stream = createReadStream(filePath, { start: 0 });
      const chunks: Buffer[] = [];
      let bytesRead = 0;
      let headerLength = 0;
      let headerBuffer: Buffer | null = null;

      stream.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        bytesRead += chunk.length;

        if (bytesRead >= 4 && headerLength === 0) {
          const allData = Buffer.concat(chunks);
          headerLength = allData.readUInt32BE(0);

          if (bytesRead >= 4 + headerLength) {
            headerBuffer = allData.subarray(4, 4 + headerLength);
            stream.destroy();
          }
        }
      });

      stream.on("close", () => {
        if (!headerBuffer) return reject(new Error("Could not read header"));
        const headerJson = headerBuffer.toString("utf8");
        const header: FileHeader = JSON.parse(headerJson);
        const encryptedDataOffset = 4 + headerLength;
        resolve({ header, encryptedDataOffset });
      });

      stream.on("error", reject);
    });
  }

  const { header, encryptedDataOffset } = await readFileHeader(inputPath);

  await decryptFileStreaming(
    options,
    inputPath,
    outputPath,
    header,
    encryptedDataOffset
  );
}

/**
 * Decrypt a file using streaming
 */
async function decryptFileStreaming(
  options: DecryptOptions,
  inputPath: string,
  outputPath: string,
  header: FileHeader,
  dataOffset: number
): Promise<void> {
  const iv = Buffer.from(header.iv, "base64");
  const authTag = Buffer.from(header.authTag, "base64");

  let decipher: any;

  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric decryption");
      }
      if (!header.salt) {
        throw new Error("Salt missing from encrypted file");
      }
      const salt = Buffer.from(header.salt, "base64");
      const key = scryptSync(options.password, salt, 32);

      decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      break;

    case "openEnvelope":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for decryption");
      }
      if (!header.encryptedKey) {
        throw new Error("Encrypted key missing from file header");
      }

      const encryptedAESKey = Buffer.from(header.encryptedKey, "base64");
      const aesKey = privateDecrypt(
        {
          key: options.recipientPrivateKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        encryptedAESKey
      );

      decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
      decipher.setAuthTag(authTag);
      break;

    case "secure-channel":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for secure channel");
      }
      if (!header.ephemeralPublicKey || !header.salt) {
        throw new Error("Ephemeral public key or salt missing from header");
      }

      // ✅ FIXED: Use deriveAESKeyForDecryption with salt from header
      const sharedSecret = deriveAESKeyForDecryption(
        options.recipientPrivateKey,
        header.ephemeralPublicKey,
        Buffer.from(header.salt, "base64")
      );

      decipher = createDecipheriv("aes-256-gcm", sharedSecret, iv);
      decipher.setAuthTag(authTag);
      break;

    default:
      throw new Error(`Unsupported decryption type: ${options}`);
  }

  const inputStream = createReadStream(inputPath, { start: dataOffset });
  const outputStream = createWriteStream(outputPath);

  await pipeline(inputStream, decipher, outputStream);

  console.log("✅ File decrypted successfully");
}

/**
 * Decrypt a message (hex string) - returns string or parsed object
 */
function decryptMessage(
  options: DecryptOptions,
  encryptedHex: string
): string | object {
  const buffer = Buffer.from(encryptedHex, "hex");
  let offset = 0;

  const typeFlag = buffer[offset];
  const isString = typeFlag === 0x00;
  offset += 1;

  let decryptedData: string;

  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric decryption");
      }

      // Format: typeFlag(1) + salt(16) + iv(12) + tag(16) + encrypted
      const salt = buffer.subarray(offset, offset + 16);
      offset += 16;

      const ivSymmetric = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagSymmetric = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedSymmetric = buffer.subarray(offset);

      const key = scryptSync(options.password, salt, 32);

      const decipherSymmetric = createDecipheriv(
        "aes-256-gcm",
        key,
        ivSymmetric
      );
      decipherSymmetric.setAuthTag(tagSymmetric);

      decryptedData = Buffer.concat([
        decipherSymmetric.update(encryptedSymmetric),
        decipherSymmetric.final(),
      ]).toString("utf8");
      break;

    case "openEnvelope":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for decryption");
      }

      // Format: typeFlag(1) + encryptedKeyLength(2) + encryptedKey + iv(12) + tag(16) + encrypted
      const encryptedKeyLength = buffer.readUInt16BE(offset);
      offset += 2;

      const encryptedKey = buffer.subarray(offset, offset + encryptedKeyLength);
      offset += encryptedKeyLength;

      const ivRSA = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagRSA = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedRSA = buffer.subarray(offset);

      const aesKey = privateDecrypt(
        {
          key: options.recipientPrivateKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        encryptedKey
      );

      const decipherRSA = createDecipheriv("aes-256-gcm", aesKey, ivRSA);
      decipherRSA.setAuthTag(tagRSA);

      decryptedData = Buffer.concat([
        decipherRSA.update(encryptedRSA),
        decipherRSA.final(),
      ]).toString("utf8");
      break;

    case "secure-channel":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for secure channel");
      }

      // ✅ FIXED: Format matches encryption
      // Format: typeFlag(1) + ephemeralPubKeyLen(2) + ephemeralPubKey + salt(16) + iv(12) + tag(16) + encrypted
      const ephemeralKeyLength = buffer.readUInt16BE(offset);
      offset += 2;

      const ephemeralPublicKey = buffer.subarray(
        offset,
        offset + ephemeralKeyLength
      );
      offset += ephemeralKeyLength;

      const saltECDH = buffer.subarray(offset, offset + 16);
      offset += 16;

      const ivECDH = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagECDH = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedECDH = buffer.subarray(offset);

      // ✅ FIXED: Use deriveAESKeyForDecryption
      const sharedSecret = deriveAESKeyForDecryption(
        options.recipientPrivateKey,
        ephemeralPublicKey.toString("base64"),
        saltECDH
      );

      const decipherECDH = createDecipheriv(
        "aes-256-gcm",
        sharedSecret,
        ivECDH
      );
      decipherECDH.setAuthTag(tagECDH);

      decryptedData = Buffer.concat([
        decipherECDH.update(encryptedECDH),
        decipherECDH.final(),
      ]).toString("utf8");
      break;

    default:
      throw new Error(`Unsupported decryption type: ${options}`);
  }

  return isString ? decryptedData : JSON.parse(decryptedData);
}

/**
 * Recipient side: derives AES key from ephemeral public key
 * ✅ MATCHES encryption function signature
 */
function deriveAESKeyForDecryption(
  recipientPrivateKeyStr: string,
  ephemeralPublicKeyStr: string,
  salt: Buffer
): Buffer {
  const recipient = createECDH("prime256v1");
  const recipientPrivateKey = Buffer.from(recipientPrivateKeyStr, "base64");
  recipient.setPrivateKey(recipientPrivateKey);

  const ephemeralPublicKey = Buffer.from(ephemeralPublicKeyStr, "base64");
  const sharedSecret = recipient.computeSecret(ephemeralPublicKey);

  // ✅ FIXED: Convert ArrayBuffer to Buffer (same as encryption)
  const aesKey = Buffer.from(
    hkdfSync("sha256", sharedSecret, salt, "secure-channel as key", 32)
  );

  return aesKey;
}

// Export functions
export { decrypt, decryptFile, decryptMessage, deriveAESKeyForDecryption };
