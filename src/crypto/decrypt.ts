import * as Stream from "stream";
import { createReadStream, createWriteStream } from "fs";
import {
  createDecipheriv,
  privateDecrypt,
  constants,
  scryptSync,
  createECDH,
  createHash,
} from "crypto";
import { pipeline } from "stream/promises";
import { tmpdir } from "os";
import { join } from "path";

interface FileHeader {
  encryptedKey?: string; // base64 - for RSA modes
  iv: string; // base64
  authTag: string; // base64
  salt?: string; // base64 - for password mode
}

type EncryptionType = "symmetric-password" | "openEnvelope" | "secure-channel";

interface DecryptOptions {
  type: EncryptionType;
  password?: string; // for symmetric
  recipientPrivateKey?: string; // for RSA modes
  senderPublicKey?: string; // for ECDH
}

interface DecryptResult {
  type: "file" | "message";
  data?: string | object; // for messages (auto-parsed if JSON)
  outputPath?: string; // for files
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

  // Detect if we're dealing with a file or message
  const isFile = inputPath && outputPath;

  if (isFile) {
    // File decryption
    await decryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    // Message decryption (hex string)
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
  // Read header length (4 bytes)

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

        // Once we have at least 4 bytes, read header length
        if (bytesRead >= 4 && headerLength === 0) {
          const allData = Buffer.concat(chunks);
          headerLength = allData.readUInt32BE(0);

          // If we already have enough bytes for the full header, slice it
          if (bytesRead >= 4 + headerLength) {
            headerBuffer = allData.subarray(4, 4 + headerLength);
            stream.destroy(); // Stop reading more
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

  // Read header JSON
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
 * Decrypt a file using streaming (memory-efficient for large files)
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

      // Decrypt the AES key using recipient's private key
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
      if (!options.recipientPrivateKey || !options.senderPublicKey) {
        throw new Error(
          "Both recipient private key and sender public key required for secure channel"
        );
      }

      const sharedSecret = deriveAESKeyFromECDH(
        options.recipientPrivateKey,
        options.senderPublicKey
      );

      decipher = createDecipheriv("aes-256-gcm", sharedSecret, iv);
      decipher.setAuthTag(authTag);
      break;

    default:
      throw new Error(`Unsupported decryption type: ${options.type}`);
  }

  // Create read stream starting at encrypted data offset
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

  // Read type flag (first byte)
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

      // Derive key from password
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

      // Decrypt the AES key
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
      if (!options.recipientPrivateKey || !options.senderPublicKey) {
        throw new Error(
          "Both recipient private key and sender public key required for secure channel"
        );
      }

      // Format: typeFlag(1) + iv(12) + tag(16) + encrypted
      const ivECDH = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagECDH = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedECDH = buffer.subarray(offset);

      const sharedSecret = deriveAESKeyFromECDH(
        options.recipientPrivateKey,
        options.senderPublicKey
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
      throw new Error(`Unsupported decryption type: ${options.type}`);
  }

  // Return based on type flag
  return isString ? decryptedData : JSON.parse(decryptedData);
}

/**
 * Derive AES key from ECDH shared secret (same as encryption)
 */
function deriveAESKeyFromECDH(
  privateKeyStr: string,
  publicKeyStr: string
): Buffer {
  const ecdh = createECDH("prime256v1");

  const privateKey = Buffer.from(privateKeyStr, "base64");
  const publicKey = Buffer.from(publicKeyStr, "base64");

  ecdh.setPrivateKey(privateKey);
  const sharedSecret = ecdh.computeSecret(publicKey);

  // Hash to get AES-256 key (32 bytes)
  return createHash("sha256").update(sharedSecret).digest();
}

// Export functions
export { decrypt, decryptFile, decryptMessage, deriveAESKeyFromECDH };
