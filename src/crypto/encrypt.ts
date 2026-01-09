import * as Stream from "stream";
import { createReadStream, createWriteStream, statSync } from "fs";
import {
  createCipheriv,
  publicEncrypt,
  randomBytes,
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

type EncryptionType = "symmetric-password" | "sealEnvelope" | "secure-channel";

interface EncryptOptions {
  type: EncryptionType;
  password?: string; // for symmetric
  recipientPublicKey?: string; // for RSA/ECDH
  senderPrivateKey?: string; // for ECDH
  stream?: boolean; // true for big files
}

interface EncryptResult {
  type: "file" | "message";
  data?: string; // hex string for messages
  outputPath?: string; // for files
}

/**
 * Main encryption function - handles both messages and files
 */
async function encrypt(
  options: EncryptOptions,
  data: Buffer | Stream.Readable | string | object | any,
  inputPath?: string,
  outputPath?: string
): Promise<EncryptResult> {
  if (!data) {
    throw new Error("No data to encrypt");
  }

  // Detect if we're dealing with a file or message
  const isFile = inputPath && outputPath;

  if (isFile) {
    // File encryption
    await encryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    // Message encryption (string, object, or Buffer)
    let messageData: string | object | any;

    if (Buffer.isBuffer(data)) {
      messageData = data.toString("utf8");
    } else if (typeof data === "string") {
      messageData = data;
    } else {
      // It's an object - pass it directly
      messageData = data;
    }

    const encrypted = encryptMessage(options, messageData);
    return { type: "message", data: encrypted };
  }
}

/**
 * Encrypt a file (automatically uses streaming for large files)
 */
async function encryptFile(
  options: EncryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  const LARGE_FILE_THRESHOLD = 100 * 1024 * 1024; // 100 MB
  const fileSize = statSync(inputPath).size;

  // Use streaming for all files (especially large ones)
  if (fileSize > LARGE_FILE_THRESHOLD || options.stream) {
    await encryptFileStreaming(options, inputPath, outputPath);
  } else {
    await encryptFileStreaming(options, inputPath, outputPath);
  }
}

/**
 * Encrypt a file using streaming (memory-efficient for large files)
 */
async function encryptFileStreaming(
  options: EncryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  const tempPath = join(tmpdir(), `temp-encrypt-${Date.now()}.tmp`);
  const tempStream = createWriteStream(tempPath);
  const inputStream = createReadStream(inputPath);

  let header: FileHeader;

  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric encryption");
      }
      const salt = randomBytes(16);
      const key = scryptSync(options.password, salt, 32);
      const cipherSymmetric = createCipheriv("aes-256-gcm", key, iv);

      await pipeline(inputStream, cipherSymmetric, tempStream);
      const authTagSymmetric = cipherSymmetric.getAuthTag();

      header = {
        iv: iv.toString("base64"),
        authTag: authTagSymmetric.toString("base64"),
        salt: salt.toString("base64"),
      };
      break;

    case "sealEnvelope":
      if (!options.recipientPublicKey) {
        throw new Error("Recipient public key required for seal mode");
      }
      const cipherSeal = createCipheriv("aes-256-gcm", aesKey, iv);

      await pipeline(inputStream, cipherSeal, tempStream);
      const authTagSeal = cipherSeal.getAuthTag();

      // Encrypt the AES key with recipient's public key
      const encryptedAESKey = publicEncrypt(
        {
          key: options.recipientPublicKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        aesKey
      );

      header = {
        encryptedKey: encryptedAESKey.toString("base64"),
        iv: iv.toString("base64"),
        authTag: authTagSeal.toString("base64"),
      };
      break;

    case "secure-channel":
      if (!options.senderPrivateKey || !options.recipientPublicKey) {
        throw new Error(
          "Both sender and recipient keys required for secure channel"
        );
      }
      const sharedSecret = deriveAESKeyFromECDH(
        options.senderPrivateKey,
        options.recipientPublicKey
      );

      const cipherECDH = createCipheriv("aes-256-gcm", sharedSecret, iv);
      await pipeline(inputStream, cipherECDH, tempStream);
      const authTagECDH = cipherECDH.getAuthTag();

      header = {
        iv: iv.toString("base64"),
        authTag: authTagECDH.toString("base64"),
      };
      break;

    default:
      throw new Error(`Unsupported encryption type: ${options.type}`);
  }

  // Write final output with header
  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerLengthBuf = Buffer.alloc(4);
  headerLengthBuf.writeUInt32BE(headerJson.length, 0);

  const outputStream = createWriteStream(outputPath);

  // Write header first
  outputStream.write(headerLengthBuf);
  outputStream.write(headerJson);

  // Stream encrypted data from temp file
  const tempReadStream = createReadStream(tempPath);
  await pipeline(tempReadStream, outputStream);

  // Clean up temp file
  try {
    const { unlinkSync } = await import("fs");
    unlinkSync(tempPath);
  } catch (e) {
    console.warn("Could not delete temp file:", tempPath);
  }

  console.log("✅ File encrypted successfully");
}

/**
 * Encrypt a message (string, object, or any JSON-serializable data) - returns hex string
 */
function encryptMessage(
  options: EncryptOptions,
  data: string | object | any
): string {
  // Determine data type and serialize if needed
  const isString = typeof data === "string";
  const stringData = isString ? data : JSON.stringify(data);

  // Type flag: 0x00 = string, 0x01 = json
  const typeFlag = Buffer.from([isString ? 0x00 : 0x01]);

  const iv = randomBytes(12);
  const aesKey = randomBytes(32);

  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric encryption");
      }
      const salt = randomBytes(16);
      const key = scryptSync(options.password, salt, 32);
      const cipher = createCipheriv("aes-256-gcm", key, iv);

      const encrypted = Buffer.concat([
        cipher.update(stringData, "utf8"),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      // Format: typeFlag(1) + salt(16) + iv(12) + tag(16) + encrypted
      return Buffer.concat([typeFlag, salt, iv, tag, encrypted]).toString(
        "hex"
      );

    case "sealEnvelope":
      if (!options.recipientPublicKey) {
        throw new Error("Recipient public key required for seal mode");
      }
      const cipherSeal = createCipheriv("aes-256-gcm", aesKey, iv);

      const encryptedSeal = Buffer.concat([
        cipherSeal.update(stringData, "utf8"),
        cipherSeal.final(),
      ]);
      const tagSeal = cipherSeal.getAuthTag();

      // Encrypt the AES key with recipient's public key
      const encryptedKey = publicEncrypt(
        {
          key: options.recipientPublicKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        aesKey
      );

      // Format: typeFlag(1) + encryptedKeyLength(2) + encryptedKey + iv(12) + tag(16) + encrypted
      const keyLengthBuf = Buffer.alloc(2);
      keyLengthBuf.writeUInt16BE(encryptedKey.length, 0);

      return Buffer.concat([
        typeFlag, // ← ADD THIS
        keyLengthBuf,
        encryptedKey,
        iv,
        tagSeal,
        encryptedSeal,
      ]).toString("hex");

    case "secure-channel":
      if (!options.senderPrivateKey || !options.recipientPublicKey) {
        throw new Error(
          "Both sender and recipient keys required for secure channel"
        );
      }

      const sharedSecret = deriveAESKeyFromECDH(
        options.senderPrivateKey,
        options.recipientPublicKey
      );

      const cipherECDH = createCipheriv("aes-256-gcm", sharedSecret, iv);
      const encryptedECDH = Buffer.concat([
        cipherECDH.update(stringData, "utf8"),
        cipherECDH.final(),
      ]);
      const tagECDH = cipherECDH.getAuthTag();

      // Format: typeFlag(1) + iv(12) + tag(16) + encrypted
      return Buffer.concat([typeFlag, iv, tagECDH, encryptedECDH]).toString(
        "hex"
      );

    default:
      throw new Error(`Unsupported encryption type: ${options.type}`);
  }
}

/**
 * Derive AES key from ECDH shared secret
 */
function deriveAESKeyFromECDH(
  senderPrivateKeyStr: string,
  recipientPublicKeyStr: string
): Buffer {
  const ecdh = createECDH("prime256v1");

  const senderPrivateKey = Buffer.from(senderPrivateKeyStr, "base64");
  const recipientPublicKey = Buffer.from(recipientPublicKeyStr, "base64");

  ecdh.setPrivateKey(senderPrivateKey);
  const sharedSecret = ecdh.computeSecret(recipientPublicKey);

  // Hash to get AES-256 key (32 bytes)
  return createHash("sha256").update(sharedSecret).digest();
}

// Export functions
export { encrypt, encryptFile, encryptMessage, deriveAESKeyFromECDH };
