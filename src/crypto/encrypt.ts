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
  hkdf,
  hkdfSync,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  KeyObject,
} from "crypto";
import { pipeline } from "stream/promises";
import { tmpdir } from "os";
import { join } from "path";

/**
 * Result of encryption
 */
interface EncryptResult {
  type: "file" | "message";
  data?: string;
  outputPath?: string;
}

interface FileHeader {
  encryptedKey?: string; // base64 - for RSA modes
  ephemeralPublicKey?: string; // base64 - for ECDH mode ← ADD THIS
  iv: string; // base64
  authTag: string; // base64
  salt?: string; // base64 - for password mode AND ECDH mode ← UPDATED
}

type EncryptOptions =
  | { type: "symmetric-password"; password: string; stream?: boolean }
  | { type: "sealEnvelope"; recipientPublicKey: string; stream?: boolean }
  | {
      type: "secure-channel";
      recipientPublicKey: string;
      stream?: boolean;
    };

// Message mode
/**
 * Encrypt a message with a password
 * @param options.type "symmetric-password"
 * @param options.password Required password for AES-256-GCM
 * @param options.stream Optional, use streaming for large files
 * @param data The data to encrypt (string, Buffer, or JSON-serializable object)
 * @returns Hex string wrapped in EncryptResult
 * @example
 * ```ts
 * const result = await encrypt({ type: "symmetric-password", password: "secret" }, "Hello");
 * console.log(result.data); // Hex string
 * ```
 */
function encrypt(
  options: { type: "symmetric-password"; password: string; stream?: boolean },
  data: string | object | Buffer
): Promise<EncryptResult>;

/**
 * Encrypt a message for RSA envelope ("sealEnvelope")
 * @param options.type "sealEnvelope"
 * @param options.recipientPublicKey Recipient's public key (Base64)
 * @param options.stream Optional, use streaming for large files
 * @param data The data to encrypt (string, Buffer, or JSON-serializable object)
 * @returns Hex string wrapped in EncryptResult
 * @example
 * ```ts
 * const result = await encrypt({ type: "sealEnvelope", recipientPublicKey: pubKey }, "Hello");
 * console.log(result.data); // Hex string
 * ```
 */
function encrypt(
  options: {
    type: "sealEnvelope";
    recipientPublicKey: string;
    stream?: boolean;
  },
  data: string | object | Buffer
): Promise<EncryptResult>;

/**
 * Encrypt a message for secure ECDH channel
 * @param options.type "secure-channel"
 * @param options.recipientPublicKey Recipient's public key (Base64)
 * @param options.stream Optional, use streaming for large files
 * @param data The data to encrypt (string, Buffer, or JSON-serializable object)
 * @returns Hex string wrapped in EncryptResult
 * @example
 * ```ts
 * const result = await encrypt({ type: "secure-channel", senderPrivateKey: priv, recipientPublicKey: pub }, "Hello");
 * console.log(result.data); // Hex string
 * ```
 */
function encrypt(
  options: {
    type: "secure-channel";
    recipientPublicKey: string;
    stream?: boolean;
  },
  data: string | object | Buffer
): Promise<EncryptResult>;

// File mode
/**
 * File mode overload: encrypt a file with password
 * @param options.type "symmetric-password"
 * @param options.password Password string for encryption
 * @param options.stream Optional streaming mode
 * @param data Optional buffer (can be undefined if using file mode)
 * @param inputPath Path to input file
 * @param outputPath Path to write encrypted output file
 * @returns EncryptResult with outputPath
 * @example
 * ```ts
 * await encrypt({ type: "symmetric-password", password: "secret" }, undefined, "./input.txt", "./encrypted.bin");
 * ```
 */
function encrypt(
  options: { type: "symmetric-password"; password: string; stream?: boolean },
  data: Buffer | Stream.Readable | string | object | undefined,
  inputPath: string,
  outputPath: string
): Promise<EncryptResult>;

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
      if (!options.recipientPublicKey) {
        throw new Error("Recipient public key required for secure channel");
      }

      // Generate ephemeral key - FIX: use correct variable names
      const ephemeralData = deriveAESKeyForEncryption(
        options.recipientPublicKey
      );

      // FIX: Use the returned aesKey, not the random one
      const cipherECDH = createCipheriv(
        "aes-256-gcm",
        ephemeralData.aesKey,
        iv
      );
      await pipeline(inputStream, cipherECDH, tempStream);
      const authTagECDH = cipherECDH.getAuthTag();

      header = {
        ephemeralPublicKey: ephemeralData.ephemeralPublicKey,
        salt: ephemeralData.salt.toString("base64"),
        iv: iv.toString("base64"),
        authTag: authTagECDH.toString("base64"),
      };
      break;

    default:
      throw new Error(`Unsupported encryption type: ${options}`);
  }

  // Write final output with header
  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerLengthBuf = Buffer.alloc(4);
  headerLengthBuf.writeUInt32BE(headerJson.length, 0);

  const outputStream = createWriteStream(outputPath);

  outputStream.write(headerLengthBuf);
  outputStream.write(headerJson);

  const tempReadStream = createReadStream(tempPath);
  await pipeline(tempReadStream, outputStream);

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
  const isString = typeof data === "string";
  const stringData = isString ? data : JSON.stringify(data);
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

      const encryptedKey = publicEncrypt(
        {
          key: options.recipientPublicKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        aesKey
      );

      const keyLengthBuf = Buffer.alloc(2);
      keyLengthBuf.writeUInt16BE(encryptedKey.length, 0);

      return Buffer.concat([
        typeFlag,
        keyLengthBuf,
        encryptedKey,
        iv,
        tagSeal,
        encryptedSeal,
      ]).toString("hex");

    case "secure-channel":
      if (!options.recipientPublicKey) {
        throw new Error("Recipient public key required for secure channel");
      }

      // Generate ephemeral key and derive shared secret
      const ephemeralData = deriveAESKeyForEncryption(
        options.recipientPublicKey
      );

      const cipherECDH = createCipheriv(
        "aes-256-gcm",
        ephemeralData.aesKey,
        iv
      );
      const encryptedECDH = Buffer.concat([
        cipherECDH.update(stringData, "utf8"),
        cipherECDH.final(),
      ]);
      const tagECDH = cipherECDH.getAuthTag();

      // Format: typeFlag(1) + ephemeralPubKeyLen(2) + ephemeralPubKey + salt(16) + iv(12) + tag(16) + encrypted
      const ephemeralKeyBuffer = Buffer.from(
        ephemeralData.ephemeralPublicKey,
        "base64"
      );
      const ephemeralKeyLenBuf = Buffer.alloc(2);
      ephemeralKeyLenBuf.writeUInt16BE(ephemeralKeyBuffer.length, 0);

      return Buffer.concat([
        typeFlag,
        ephemeralKeyLenBuf,
        ephemeralKeyBuffer,
        ephemeralData.salt,
        iv,
        tagECDH,
        encryptedECDH,
      ]).toString("hex");

    default:
      throw new Error(`Unsupported encryption type: ${options}`);
  }
}

/**
 * Sender side: generates ephemeral key and derives AES key
 * FIX: Return proper types and convert ArrayBuffer to Buffer
 */
function deriveAESKeyForEncryption(recipientPublicKeyStr: string): {
  aesKey: Buffer;
  ephemeralPublicKey: string;
  ephemeralPrivateKey: KeyObject;
  salt: Buffer;
} {
  // Genera chiave effimera X25519
  const { publicKey, privateKey } = generateKeyPairSync("x25519");

  // Chiave pubblica destinatario
  const recipientPublicKey = createPublicKey({
    key: Buffer.from(recipientPublicKeyStr, "base64"),
    format: "der",
    type: "spki",
  });

  const salt = randomBytes(16);

  // Shared secret
  const sharedSecret = diffieHellman({
    privateKey,
    publicKey: recipientPublicKey,
  });

  // Deriva AES key con HKDF
  const aesKey = Buffer.from(
    hkdfSync("sha256", sharedSecret, salt, "secure-channel as key", 32)
  );

  return {
    aesKey,
    ephemeralPublicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    ephemeralPrivateKey: privateKey,
    salt,
  };
}

/**
 * Lato destinatario: derive AES key da chiave effimera del mittente
 */
function deriveAESKeyForDecryption(
  recipientPrivateKeyStr: string,
  ephemeralPublicKeyStr: string,
  salt: Buffer
): Buffer {
  const recipientPrivateKey = createPrivateKey({
    key: Buffer.from(recipientPrivateKeyStr, "base64"),
    format: "der",
    type: "pkcs8",
  });

  const ephemeralPublicKey = createPublicKey({
    key: Buffer.from(ephemeralPublicKeyStr, "base64"),
    format: "der",
    type: "spki",
  });

  const sharedSecret = diffieHellman({
    privateKey: recipientPrivateKey,
    publicKey: ephemeralPublicKey,
  });

  const aesKey = Buffer.from(
    hkdfSync("sha256", sharedSecret, salt, "secure-channel as key", 32)
  );

  return aesKey;
}

// Export functions
export {
  encrypt,
  encryptMessage,
  encryptFileStreaming,
  deriveAESKeyForEncryption,
  deriveAESKeyForDecryption,
};
