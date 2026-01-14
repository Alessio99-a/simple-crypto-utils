import { createReadStream, createWriteStream } from "fs";
import { unlink } from "fs/promises";
import {
  createCipheriv,
  publicEncrypt,
  randomBytes,
  constants,
  scryptSync,
  hkdfSync,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  KeyObject,
  sign,
} from "crypto";
import { pipeline } from "stream/promises";
import { tmpdir } from "os";
import { join } from "path";

// ============================================
// CONSTANTS & VERSION
// ============================================

const VERSION = 0x01;
const MIN_PASSWORD_LENGTH = 12;
const MESSAGE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minuti

// ============================================
// TYPES & INTERFACES
// ============================================

interface EncryptResult {
  type: "file" | "message";
  data?: string;
  outputPath?: string;
}

interface FileHeader {
  version: number;
  encryptedKey?: string;
  ephemeralPublicKey?: string;
  signature?: string;
  iv: string;
  authTag: string;
  salt?: string;
  timestamp?: number;
}

interface SymmetricPasswordOptions {
  type: "symmetric-password";
  password: string;
  strictMode?: boolean;
}

interface SealEnvelopeOptions {
  type: "sealEnvelope";
  recipientPublicKey: string;
  strictMode?: boolean;
}

interface SecureChannelOptions {
  type: "secure-channel";
  recipientPublicKey: string;
  includeTimestamp?: boolean;
  strictMode?: boolean;
}

interface AuthenticatedChannelOptions {
  type: "authenticated-channel";
  recipientPublicKey: string;
  senderPrivateKey: string;
  includeTimestamp?: boolean;
  strictMode?: boolean;
}

type MessageEncryptOptions =
  | SymmetricPasswordOptions
  | SealEnvelopeOptions
  | SecureChannelOptions
  | AuthenticatedChannelOptions;

type MessageData = string | object | Buffer;

// ============================================
// VALIDATION FUNCTIONS
// ============================================

/**
 * Validates password strength
 * @param password - The password to validate
 * @param strictMode - If true, enforces stricter validation rules
 * @throws {Error} If password is too short or doesn't meet requirements
 * @example
 * validatePassword("MyP@ssw0rd123", false);
 */
function validatePassword(password: string, strictMode: boolean = false): void {
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters`
    );
  }

  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  const strength = [hasUpperCase, hasLowerCase, hasNumber, hasSpecial].filter(
    Boolean
  ).length;

  if (strictMode && strength < 3) {
    throw new Error(
      "Strict mode: password must contain uppercase, lowercase, numbers, and special characters"
    );
  }

  if (!strictMode && strength < 2) {
    console.warn(
      "⚠️ Weak password: consider using uppercase, lowercase, numbers, and special characters"
    );
  }
}

/**
 * Validates public key format and type
 * @param keyStr - Base64-encoded public key in SPKI format
 * @param expectedType - Expected key type ('rsa' or 'x25519')
 * @throws {Error} If key is invalid or doesn't match expected type
 * @example
 * validatePublicKey("MIIBIjANBgkq...", "rsa");
 */
function validatePublicKey(
  keyStr: string,
  expectedType: "rsa" | "x25519"
): void {
  try {
    const keyBuffer = Buffer.from(keyStr, "base64");
    const key = createPublicKey({
      key: keyBuffer,
      format: "der",
      type: "spki",
    });

    if (key.asymmetricKeyType !== expectedType) {
      throw new Error(
        `Expected ${expectedType} key, got ${key.asymmetricKeyType}`
      );
    }
  } catch (err: any) {
    throw new Error(`Invalid ${expectedType} public key: ${err.message}`);
  }
}

/**
 * Validates private key format and type
 * @param keyStr - Base64-encoded private key in PKCS8 format
 * @param expectedType - Expected key type ('rsa' or 'ed25519')
 * @throws {Error} If key is invalid or doesn't match expected type
 * @example
 * validatePrivateKey("MIIEvQIBADANBgkq...", "ed25519");
 */
function validatePrivateKey(
  keyStr: string,
  expectedType: "rsa" | "ed25519"
): void {
  try {
    const keyBuffer = Buffer.from(keyStr, "base64");
    const key = createPrivateKey({
      key: keyBuffer,
      format: "der",
      type: "pkcs8",
    });

    if (key.asymmetricKeyType !== expectedType) {
      throw new Error(
        `Expected ${expectedType} key, got ${key.asymmetricKeyType}`
      );
    }
  } catch (err: any) {
    throw new Error(`Invalid ${expectedType} private key: ${err.message}`);
  }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Securely delete temporary file
 * @param filePath - Path to the file to delete
 * @example
 * await secureDelete("/tmp/tempfile.tmp");
 */
async function secureDelete(filePath: string): Promise<void> {
  try {
    await unlink(filePath);
  } catch (err: any) {
    console.error(`⚠️ Failed to delete temp file ${filePath}:`, err.message);
  }
}

/**
 * Create timestamp buffer for replay protection
 * @returns Buffer containing current timestamp as BigUInt64BE
 * @example
 * const timestamp = createTimestampBuffer();
 */
function createTimestampBuffer(): Buffer {
  const timestamp = Date.now();
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestamp), 0);
  return buf;
}

// ============================================
// MAIN ENCRYPTION FUNCTIONS - OVERLOADS
// ============================================

/**
 * Encrypt a message with symmetric password encryption
 * @param options - Symmetric password encryption options
 * @param data - Data to encrypt (string, object, or Buffer)
 * @returns Promise resolving to encryption result with hex-encoded data
 * @example
 * const result = await encrypt(
 *   { type: "symmetric-password", password: "MySecureP@ss123" },
 *   "Secret message"
 * );
 * console.log(result.data); // hex string
 */
function encrypt(
  options: SymmetricPasswordOptions,
  data: MessageData
): Promise<EncryptResult>;

/**
 * Encrypt a message using RSA sealed envelope
 * @param options - Sealed envelope encryption options
 * @param data - Data to encrypt (string, object, or Buffer)
 * @returns Promise resolving to encryption result with hex-encoded data
 * @example
 * const result = await encrypt(
 *   {
 *     type: "sealEnvelope",
 *     recipientPublicKey: "MIIBIjANBgkq..."
 *   },
 *   { message: "Secret data", value: 42 }
 * );
 */
function encrypt(
  options: SealEnvelopeOptions,
  data: MessageData
): Promise<EncryptResult>;

/**
 * Encrypt a message using ECDH secure channel
 * @param options - Secure channel encryption options
 * @param data - Data to encrypt (string, object, or Buffer)
 * @returns Promise resolving to encryption result with hex-encoded data
 * @example
 * const result = await encrypt(
 *   {
 *     type: "secure-channel",
 *     recipientPublicKey: "MCowBQYDK2VuAyEA...",
 *     includeTimestamp: true
 *   },
 *   "Timestamped message"
 * );
 */
function encrypt(
  options: SecureChannelOptions,
  data: MessageData
): Promise<EncryptResult>;

/**
 * Encrypt a message using authenticated channel (ECDH + Ed25519 signature)
 * @param options - Authenticated channel encryption options
 * @param data - Data to encrypt (string, object, or Buffer)
 * @returns Promise resolving to encryption result with hex-encoded data
 * @example
 * const result = await encrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPublicKey: "MCowBQYDK2VuAyEA...",
 *     senderPrivateKey: "MC4CAQAwBQYDK2Vw...",
 *     includeTimestamp: true
 *   },
 *   "Signed and encrypted message"
 * );
 */
function encrypt(
  options: AuthenticatedChannelOptions,
  data: MessageData
): Promise<EncryptResult>;

/**
 * Encrypt a file with symmetric password encryption
 * @param options - Symmetric password encryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @returns Promise resolving to encryption result with output path
 * @example
 * const result = await encrypt(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   null,
 *   "/path/to/document.pdf",
 *   "/path/to/document.pdf.enc"
 * );
 */
function encrypt(
  options: SymmetricPasswordOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<EncryptResult>;

/**
 * Encrypt a file using RSA sealed envelope
 * @param options - Sealed envelope encryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @returns Promise resolving to encryption result with output path
 * @example
 * const result = await encrypt(
 *   { type: "sealEnvelope", recipientPublicKey: "MIIBIjANBgkq..." },
 *   null,
 *   "/path/to/video.mp4",
 *   "/path/to/video.mp4.enc"
 * );
 */
function encrypt(
  options: SealEnvelopeOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<EncryptResult>;

/**
 * Encrypt a file using ECDH secure channel
 * @param options - Secure channel encryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @returns Promise resolving to encryption result with output path
 * @example
 * const result = await encrypt(
 *   {
 *     type: "secure-channel",
 *     recipientPublicKey: "MCowBQYDK2VuAyEA...",
 *     includeTimestamp: true
 *   },
 *   null,
 *   "/path/to/archive.zip",
 *   "/path/to/archive.zip.enc"
 * );
 */
function encrypt(
  options: SecureChannelOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<EncryptResult>;

/**
 * Encrypt a file using authenticated channel
 * @param options - Authenticated channel encryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @returns Promise resolving to encryption result with output path
 * @example
 * const result = await encrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPublicKey: "MCowBQYDK2VuAyEA...",
 *     senderPrivateKey: "MC4CAQAwBQYDK2Vw...",
 *     includeTimestamp: true
 *   },
 *   null,
 *   "/path/to/backup.tar.gz",
 *   "/path/to/backup.tar.gz.enc"
 * );
 */
function encrypt(
  options: AuthenticatedChannelOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<EncryptResult>;

// Implementation
async function encrypt(
  options: MessageEncryptOptions,
  data: MessageData | null | undefined,
  inputPath?: string,
  outputPath?: string
): Promise<EncryptResult> {
  if (!data && !inputPath) {
    throw new Error("No data to encrypt");
  }

  if (options.strictMode) {
    console.log("🔒 Strict mode enabled - all security checks active");
  }

  const isFile = inputPath && outputPath;

  if (isFile) {
    await encryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    let messageData: MessageData;

    if (Buffer.isBuffer(data)) {
      messageData = data.toString("utf8");
    } else if (typeof data === "string") {
      messageData = data;
    } else {
      messageData = data!;
    }

    const encrypted = encryptMessage(options, messageData);
    return { type: "message", data: encrypted };
  }
}

// ============================================
// FILE ENCRYPTION
// ============================================

/**
 * Encrypt a file using streaming for memory efficiency
 * @param options - Encryption options
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @example
 * await encryptFile(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   "./document.pdf",
 *   "./document.pdf.enc"
 * );
 */
async function encryptFile(
  options: MessageEncryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  await encryptFileStreaming(options, inputPath, outputPath);
}

/**
 * Encrypt a file using streaming (memory-efficient for large files)
 * @param options - Encryption options
 * @param inputPath - Path to input file
 * @param outputPath - Path to output encrypted file
 * @throws {Error} If encryption fails
 * @example
 * await encryptFileStreaming(
 *   { type: "sealEnvelope", recipientPublicKey: "MIIBIjANBgkq..." },
 *   "./large-video.mp4",
 *   "./large-video.mp4.enc"
 * );
 */
async function encryptFileStreaming(
  options: MessageEncryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  const tempPath = join(
    tmpdir(),
    `temp-encrypt-${Date.now()}-${randomBytes(4).toString("hex")}.tmp`
  );

  try {
    const tempStream = createWriteStream(tempPath);
    const inputStream = createReadStream(inputPath);

    let header: FileHeader;

    switch (options.type) {
      case "symmetric-password":
        validatePassword(options.password, options.strictMode);

        const salt = randomBytes(16);
        const key = scryptSync(options.password, salt, 32);
        const cipherSymmetric = createCipheriv("aes-256-gcm", key, iv);

        await pipeline(inputStream, cipherSymmetric, tempStream);
        const authTagSymmetric = cipherSymmetric.getAuthTag();

        header = {
          version: VERSION,
          iv: iv.toString("base64"),
          authTag: authTagSymmetric.toString("base64"),
          salt: salt.toString("base64"),
        };
        break;

      case "sealEnvelope":
        validatePublicKey(options.recipientPublicKey, "rsa");

        const cipherSeal = createCipheriv("aes-256-gcm", aesKey, iv);
        await pipeline(inputStream, cipherSeal, tempStream);
        const authTagSeal = cipherSeal.getAuthTag();

        // Convert base64 DER to KeyObject
        const recipientPubKey = createPublicKey({
          key: Buffer.from(options.recipientPublicKey, "base64"),
          format: "der",
          type: "spki",
        });

        const encryptedAESKey = publicEncrypt(
          {
            key: recipientPubKey, // Use KeyObject instead of string
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
          },
          aesKey
        );

        header = {
          version: VERSION,
          encryptedKey: encryptedAESKey.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagSeal.toString("base64"),
        };
        break;

      case "secure-channel":
        validatePublicKey(options.recipientPublicKey, "x25519");

        const ephemeralData = deriveAESKeyForEncryption(
          options.recipientPublicKey
        );
        const cipherECDH = createCipheriv(
          "aes-256-gcm",
          ephemeralData.aesKey,
          iv
        );

        await pipeline(inputStream, cipherECDH, tempStream);
        const authTagECDH = cipherECDH.getAuthTag();

        header = {
          version: VERSION,
          ephemeralPublicKey: ephemeralData.ephemeralPublicKey,
          salt: ephemeralData.salt.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagECDH.toString("base64"),
        };

        if (options.includeTimestamp !== false) {
          header.timestamp = Date.now();
        }
        break;

      case "authenticated-channel":
        validatePublicKey(options.recipientPublicKey, "x25519");
        validatePrivateKey(options.senderPrivateKey, "ed25519");

        const ephemeralAuthData = deriveAESKeyForEncryption(
          options.recipientPublicKey
        );
        const cipherAuth = createCipheriv(
          "aes-256-gcm",
          ephemeralAuthData.aesKey,
          iv
        );

        await pipeline(inputStream, cipherAuth, tempStream);
        const authTagAuth = cipherAuth.getAuthTag();

        const senderPrivKey = createPrivateKey({
          key: Buffer.from(options.senderPrivateKey, "base64"),
          format: "der",
          type: "pkcs8",
        });

        const dataToSign = Buffer.concat([
          Buffer.from(ephemeralAuthData.ephemeralPublicKey, "base64"),
          iv,
          authTagAuth,
        ]);

        const signature = sign(null, dataToSign, senderPrivKey);

        header = {
          version: VERSION,
          ephemeralPublicKey: ephemeralAuthData.ephemeralPublicKey,
          salt: ephemeralAuthData.salt.toString("base64"),
          signature: signature.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagAuth.toString("base64"),
        };

        if (options.includeTimestamp !== false) {
          header.timestamp = Date.now();
        }
        break;
    }

    const headerJson = Buffer.from(JSON.stringify(header), "utf8");
    const headerLengthBuf = Buffer.alloc(4);
    headerLengthBuf.writeUInt32BE(headerJson.length, 0);

    const outputStream = createWriteStream(outputPath);
    outputStream.write(headerLengthBuf);
    outputStream.write(headerJson);

    const tempReadStream = createReadStream(tempPath);
    await pipeline(tempReadStream, outputStream);

    console.log("✅ File encrypted successfully");
  } finally {
    await secureDelete(tempPath);
  }
}

// ============================================
// MESSAGE ENCRYPTION
// ============================================

/**
 * Encrypt a message (string, object, or any JSON-serializable data)
 * @param options - Encryption options
 * @param data - Data to encrypt
 * @returns Hex-encoded encrypted message
 * @example
 * const encrypted = encryptMessage(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   { user: "john", balance: 1000 }
 * );
 */
function encryptMessage(
  options: MessageEncryptOptions,
  data: MessageData
): string {
  const isString = typeof data === "string";
  const stringData = isString ? data : JSON.stringify(data);

  const versionByte = Buffer.from([VERSION]);
  const typeFlag = Buffer.from([isString ? 0x00 : 0x01]);

  const iv = randomBytes(12);
  const aesKey = randomBytes(32);

  switch (options.type) {
    case "symmetric-password":
      validatePassword(options.password, options.strictMode);

      const salt = randomBytes(16);
      const key = scryptSync(options.password, salt, 32);
      const cipher = createCipheriv("aes-256-gcm", key, iv);

      const encrypted = Buffer.concat([
        cipher.update(stringData, "utf8"),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      return Buffer.concat([
        versionByte,
        typeFlag,
        salt,
        iv,
        tag,
        encrypted,
      ]).toString("hex");

    case "sealEnvelope":
      validatePublicKey(options.recipientPublicKey, "rsa");

      const cipherSeal = createCipheriv("aes-256-gcm", aesKey, iv);

      const encryptedSeal = Buffer.concat([
        cipherSeal.update(stringData, "utf8"),
        cipherSeal.final(),
      ]);
      const tagSeal = cipherSeal.getAuthTag();

      // Convert base64 DER to KeyObject
      const recipientPubKey = createPublicKey({
        key: Buffer.from(options.recipientPublicKey, "base64"),
        format: "der",
        type: "spki",
      });

      const encryptedKey = publicEncrypt(
        {
          key: recipientPubKey, // Use KeyObject instead of string
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        aesKey
      );

      const keyLengthBuf = Buffer.alloc(2);
      keyLengthBuf.writeUInt16BE(encryptedKey.length, 0);

      return Buffer.concat([
        versionByte,
        typeFlag,
        keyLengthBuf,
        encryptedKey,
        iv,
        tagSeal,
        encryptedSeal,
      ]).toString("hex");

    case "secure-channel":
      validatePublicKey(options.recipientPublicKey, "x25519");

      const ephemeralData = deriveAESKeyForEncryption(
        options.recipientPublicKey
      );

      let dataToEncrypt = stringData;
      let hasTimestamp = false;

      if (options.includeTimestamp !== false) {
        const timestampBuf = createTimestampBuffer();
        dataToEncrypt = Buffer.concat([
          timestampBuf,
          Buffer.from(stringData, "utf8"),
        ]).toString("base64");
        hasTimestamp = true;
      }

      const cipherECDH = createCipheriv(
        "aes-256-gcm",
        ephemeralData.aesKey,
        iv
      );
      const encryptedECDH = Buffer.concat([
        cipherECDH.update(dataToEncrypt, "utf8"),
        cipherECDH.final(),
      ]);
      const tagECDH = cipherECDH.getAuthTag();

      const ephemeralKeyBuffer = Buffer.from(
        ephemeralData.ephemeralPublicKey,
        "base64"
      );
      const ephemeralKeyLenBuf = Buffer.alloc(2);
      ephemeralKeyLenBuf.writeUInt16BE(ephemeralKeyBuffer.length, 0);

      const timestampFlag = Buffer.from([hasTimestamp ? 0x01 : 0x00]);

      return Buffer.concat([
        versionByte,
        typeFlag,
        timestampFlag,
        ephemeralKeyLenBuf,
        ephemeralKeyBuffer,
        ephemeralData.salt,
        iv,
        tagECDH,
        encryptedECDH,
      ]).toString("hex");

    case "authenticated-channel":
      validatePublicKey(options.recipientPublicKey, "x25519");
      validatePrivateKey(options.senderPrivateKey, "ed25519");

      const ephemeralAuthData = deriveAESKeyForEncryption(
        options.recipientPublicKey
      );

      let dataToEncryptAuth = stringData;
      let hasTimestampAuth = false;

      if (options.includeTimestamp !== false) {
        const timestampBuf = createTimestampBuffer();
        dataToEncryptAuth = Buffer.concat([
          timestampBuf,
          Buffer.from(stringData, "utf8"),
        ]).toString("base64");
        hasTimestampAuth = true;
      }

      const cipherAuth = createCipheriv(
        "aes-256-gcm",
        ephemeralAuthData.aesKey,
        iv
      );
      const encryptedAuth = Buffer.concat([
        cipherAuth.update(dataToEncryptAuth, "utf8"),
        cipherAuth.final(),
      ]);
      const tagAuth = cipherAuth.getAuthTag();

      const senderPrivKey = createPrivateKey({
        key: Buffer.from(options.senderPrivateKey, "base64"),
        format: "der",
        type: "pkcs8",
      });

      const ephemeralKeyBufferAuth = Buffer.from(
        ephemeralAuthData.ephemeralPublicKey,
        "base64"
      );
      const dataToSign = Buffer.concat([ephemeralKeyBufferAuth, iv, tagAuth]);
      const signature = sign(null, dataToSign, senderPrivKey);

      const ephemeralKeyLenBufAuth = Buffer.alloc(2);
      ephemeralKeyLenBufAuth.writeUInt16BE(ephemeralKeyBufferAuth.length, 0);

      const signatureLenBuf = Buffer.alloc(2);
      signatureLenBuf.writeUInt16BE(signature.length, 0);

      const timestampFlagAuth = Buffer.from([hasTimestampAuth ? 0x01 : 0x00]);

      return Buffer.concat([
        versionByte,
        typeFlag,
        timestampFlagAuth,
        ephemeralKeyLenBufAuth,
        ephemeralKeyBufferAuth,
        signatureLenBuf,
        signature,
        ephemeralAuthData.salt,
        iv,
        tagAuth,
        encryptedAuth,
      ]).toString("hex");
  }
}

// ============================================
// KEY DERIVATION
// ============================================

/**
 * Generate ephemeral key pair and derive AES key using ECDH
 * @param recipientPublicKeyStr - Base64-encoded X25519 public key
 * @returns Object containing derived AES key and ephemeral keys
 * @example
 * const derived = deriveAESKeyForEncryption("MCowBQYDK2VuAyEA...");
 * console.log(derived.aesKey.length); // 32 bytes
 */
function deriveAESKeyForEncryption(recipientPublicKeyStr: string): {
  aesKey: Buffer;
  ephemeralPublicKey: string;
  ephemeralPrivateKey: KeyObject;
  salt: Buffer;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");

  const recipientPublicKey = createPublicKey({
    key: Buffer.from(recipientPublicKeyStr, "base64"),
    format: "der",
    type: "spki",
  });

  const salt = randomBytes(16);
  const sharedSecret = diffieHellman({
    privateKey,
    publicKey: recipientPublicKey,
  });

  const aesKey = Buffer.from(
    hkdfSync("sha256", sharedSecret, salt, "secure-channel-aes-key", 32)
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

// ============================================
// EXPORTS
// ============================================

export {
  encrypt,
  encryptMessage,
  encryptFileStreaming,
  deriveAESKeyForEncryption,
  validatePassword,
  validatePublicKey,
  validatePrivateKey,
  VERSION,
  MIN_PASSWORD_LENGTH,
  MESSAGE_MAX_AGE_MS,
  // Type exports for consumers
  type SymmetricPasswordOptions,
  type SealEnvelopeOptions,
  type SecureChannelOptions,
  type AuthenticatedChannelOptions,
  type MessageEncryptOptions,
  type EncryptResult,
  type FileHeader,
  type MessageData,
};
