import { createReadStream, createWriteStream } from "fs";
import {
  createDecipheriv,
  privateDecrypt,
  constants,
  scryptSync,
  hkdfSync,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  verify,
} from "crypto";
import { pipeline } from "stream/promises";
import { VERSION, MESSAGE_MAX_AGE_MS } from "./encrypt";

// ============================================
// TYPES & INTERFACES
// ============================================

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

interface DecryptMetadata {
  timestamp?: number;
  authenticated?: boolean;
}

interface MessageDecryptResult {
  type: "message";
  data: string | object;
  metadata?: DecryptMetadata;
}

interface FileDecryptResult {
  type: "file";
  outputPath: string;
  metadata?: DecryptMetadata;
}

type DecryptResult = MessageDecryptResult | FileDecryptResult;

interface SymmetricPasswordDecryptOptions {
  type: "symmetric-password";
  password: string;
  strictMode?: boolean;
}

interface OpenEnvelopeDecryptOptions {
  type: "openEnvelope";
  recipientPrivateKey: string;
  strictMode?: boolean;
}

interface SecureChannelDecryptOptions {
  type: "secure-channel";
  recipientPrivateKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

interface AuthenticatedChannelDecryptOptions {
  type: "authenticated-channel";
  recipientPrivateKey: string;
  senderPublicKey: string;
  validateTimestamp?: boolean;
  strictMode?: boolean;
}

type MessageDecryptOptions =
  | SymmetricPasswordDecryptOptions
  | OpenEnvelopeDecryptOptions
  | SecureChannelDecryptOptions
  | AuthenticatedChannelDecryptOptions;

type MessageData = string | Buffer;

// ============================================
// VALIDATION FUNCTIONS
// ============================================

/**
 * Validate timestamp to prevent replay attacks
 * @param timestamp - Unix timestamp in milliseconds
 * @param maxAge - Maximum allowed age in milliseconds
 * @throws {Error} If timestamp is invalid or too old
 * @example
 * validateTimestamp(Date.now() - 60000); // Valid: 1 minute old
 * validateTimestamp(Date.now() - 600000); // Invalid: 10 minutes old (exceeds 5 min default)
 */
function validateTimestamp(
  timestamp: number,
  maxAge: number = MESSAGE_MAX_AGE_MS
): void {
  const now = Date.now();
  const age = now - timestamp;

  if (age < 0) {
    throw new Error(
      "Message timestamp is in the future - possible clock skew or attack"
    );
  }

  if (age > maxAge) {
    throw new Error(
      `Message expired (age: ${Math.floor(age / 1000)}s, max: ${Math.floor(
        maxAge / 1000
      )}s) - possible replay attack`
    );
  }
}

/**
 * Validate format version
 * @param version - Version number from encrypted data
 * @throws {Error} If version is not supported
 * @example
 * validateVersion(0x01); // Valid
 * validateVersion(0x99); // Throws error
 */
function validateVersion(version: number): void {
  if (version !== VERSION) {
    throw new Error(
      `Unsupported format version: ${version} (expected: ${VERSION})`
    );
  }
}

// ============================================
// MAIN DECRYPTION FUNCTIONS - OVERLOADS
// ============================================

/**
 * Decrypt a message encrypted with symmetric password
 * @param options - Symmetric password decryption options
 * @param data - Hex-encoded encrypted message
 * @returns Promise resolving to decryption result with data and metadata
 * @example
 * const result = await decrypt(
 *   { type: "symmetric-password", password: "MySecureP@ss123" },
 *   "0100a1b2c3d4..." // hex string from encrypt()
 * );
 * console.log(result.data); // "Secret message" or { key: "value" }
 */
function decrypt(
  options: SymmetricPasswordDecryptOptions,
  data: MessageData
): Promise<MessageDecryptResult>;

/**
 * Decrypt a message encrypted with RSA sealed envelope
 * @param options - Open envelope decryption options
 * @param data - Hex-encoded encrypted message
 * @returns Promise resolving to decryption result with data and metadata
 * @example
 * const result = await decrypt(
 *   {
 *     type: "openEnvelope",
 *     recipientPrivateKey: "MIIEvQIBADANBgkq..."
 *   },
 *   encryptedHex
 * );
 * console.log(result.data);
 */
function decrypt(
  options: OpenEnvelopeDecryptOptions,
  data: MessageData
): Promise<MessageDecryptResult>;

/**
 * Decrypt a message encrypted with ECDH secure channel
 * @param options - Secure channel decryption options
 * @param data - Hex-encoded encrypted message
 * @returns Promise resolving to decryption result with data, timestamp, and metadata
 * @example
 * const result = await decrypt(
 *   {
 *     type: "secure-channel",
 *     recipientPrivateKey: "MC4CAQAwBQYDK2VuBCIAIE...",
 *     validateTimestamp: true
 *   },
 *   encryptedHex
 * );
 * console.log(result.metadata?.timestamp); // Unix timestamp
 */
function decrypt(
  options: SecureChannelDecryptOptions,
  data: MessageData
): Promise<MessageDecryptResult>;

/**
 * Decrypt a message encrypted with authenticated channel (ECDH + Ed25519)
 * @param options - Authenticated channel decryption options
 * @param data - Hex-encoded encrypted message
 * @returns Promise resolving to decryption result with verified data and metadata
 * @example
 * const result = await decrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPrivateKey: "MC4CAQAwBQYDK2VuBCIAIE...",
 *     senderPublicKey: "MCowBQYDK2VwAyEA...",
 *     validateTimestamp: true
 *   },
 *   encryptedHex
 * );
 * console.log(result.metadata?.authenticated); // true
 */
function decrypt(
  options: AuthenticatedChannelDecryptOptions,
  data: MessageData
): Promise<MessageDecryptResult>;

/**
 * Decrypt a file encrypted with symmetric password
 * @param options - Symmetric password decryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @returns Promise resolving to file decryption result
 * @example
 * const result = await decrypt(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   null,
 *   "./document.pdf.enc",
 *   "./document.pdf"
 * );
 * console.log(result.outputPath); // "./document.pdf"
 */
function decrypt(
  options: SymmetricPasswordDecryptOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<FileDecryptResult>;

/**
 * Decrypt a file encrypted with RSA sealed envelope
 * @param options - Open envelope decryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @returns Promise resolving to file decryption result
 * @example
 * const result = await decrypt(
 *   {
 *     type: "openEnvelope",
 *     recipientPrivateKey: "MIIEvQIBADANBgkq..."
 *   },
 *   null,
 *   "./video.mp4.enc",
 *   "./video.mp4"
 * );
 */
function decrypt(
  options: OpenEnvelopeDecryptOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<FileDecryptResult>;

/**
 * Decrypt a file encrypted with ECDH secure channel
 * @param options - Secure channel decryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @returns Promise resolving to file decryption result
 * @example
 * const result = await decrypt(
 *   {
 *     type: "secure-channel",
 *     recipientPrivateKey: "MC4CAQAwBQYDK2VuBCIAIE...",
 *     validateTimestamp: true
 *   },
 *   null,
 *   "./archive.zip.enc",
 *   "./archive.zip"
 * );
 */
function decrypt(
  options: SecureChannelDecryptOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<FileDecryptResult>;

/**
 * Decrypt a file encrypted with authenticated channel
 * @param options - Authenticated channel decryption options
 * @param data - Unused for file mode (pass null or undefined)
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @returns Promise resolving to file decryption result with authentication metadata
 * @example
 * const result = await decrypt(
 *   {
 *     type: "authenticated-channel",
 *     recipientPrivateKey: "MC4CAQAwBQYDK2VuBCIAIE...",
 *     senderPublicKey: "MCowBQYDK2VwAyEA...",
 *     validateTimestamp: true
 *   },
 *   null,
 *   "./backup.tar.gz.enc",
 *   "./backup.tar.gz"
 * );
 */
function decrypt(
  options: AuthenticatedChannelDecryptOptions,
  data: null | undefined,
  inputPath: string,
  outputPath: string
): Promise<FileDecryptResult>;

// Implementation
async function decrypt(
  options: MessageDecryptOptions,
  data: MessageData | null | undefined,
  inputPath?: string,
  outputPath?: string
): Promise<DecryptResult> {
  if (!data && !inputPath) {
    throw new Error("No data to decrypt");
  }

  if (options.strictMode) {
    console.log("🔒 Strict mode enabled - all security checks active");
  }

  const isFile = inputPath && outputPath;

  if (isFile) {
    await decryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    const encryptedHex =
      typeof data === "string" ? data : data!.toString("hex");
    const result = decryptMessage(options, encryptedHex);
    return {
      type: "message",
      data: result.data,
      metadata: result.metadata,
    };
  }
}

// ============================================
// FILE DECRYPTION
// ============================================

/**
 * Decrypt a file using streaming for memory efficiency
 * @param options - Decryption options
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @throws {Error} If decryption fails or file format is invalid
 * @example
 * await decryptFile(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   "./document.pdf.enc",
 *   "./document.pdf"
 * );
 */
async function decryptFile(
  options: MessageDecryptOptions,
  inputPath: string,
  outputPath: string
): Promise<void> {
  /**
   * Read and parse file header from encrypted file
   */
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

        validateVersion(header.version);

        const encryptedDataOffset = 4 + headerLength;
        resolve({ header, encryptedDataOffset });
      });

      stream.on("error", reject);
    });
  }

  const { header, encryptedDataOffset } = await readFileHeader(inputPath);

  // Validate timestamp if present
  if (header.timestamp) {
    const shouldValidate =
      (options.type === "secure-channel" &&
        options.validateTimestamp !== false) ||
      (options.type === "authenticated-channel" &&
        options.validateTimestamp !== false) ||
      options.strictMode;

    if (shouldValidate) {
      validateTimestamp(header.timestamp);
    }
  }

  await decryptFileStreaming(
    options,
    inputPath,
    outputPath,
    header,
    encryptedDataOffset
  );
}

/**
 * Decrypt a file using streaming (internal implementation)
 * @param options - Decryption options
 * @param inputPath - Path to encrypted file
 * @param outputPath - Path where decrypted file will be saved
 * @param header - Parsed file header with encryption metadata
 * @param dataOffset - Byte offset where encrypted data begins
 * @throws {Error} If decryption fails, signature is invalid, or required keys are missing
 * @example
 * // Internal use only - called by decryptFile()
 * await decryptFileStreaming(options, input, output, header, 128);
 */
async function decryptFileStreaming(
  options: MessageDecryptOptions,
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

      // Convert base64 DER to KeyObject
      const recipientPrivKey = createPrivateKey({
        key: Buffer.from(options.recipientPrivateKey, "base64"),
        format: "der",
        type: "pkcs8",
      });

      const aesKey = privateDecrypt(
        {
          key: recipientPrivKey, // Use KeyObject instead of string
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

      const sharedSecret = deriveAESKeyForDecryption(
        options.recipientPrivateKey,
        header.ephemeralPublicKey,
        Buffer.from(header.salt, "base64")
      );

      decipher = createDecipheriv("aes-256-gcm", sharedSecret, iv);
      decipher.setAuthTag(authTag);
      break;

    case "authenticated-channel":
      if (!options.recipientPrivateKey) {
        throw new Error(
          "Recipient private key required for authenticated channel"
        );
      }
      if (!options.senderPublicKey) {
        throw new Error(
          "Sender public key required for signature verification"
        );
      }
      if (!header.ephemeralPublicKey || !header.salt || !header.signature) {
        throw new Error(
          "Ephemeral key, salt, or signature missing from header"
        );
      }

      // Verify signature
      const senderPubKey = createPublicKey({
        key: Buffer.from(options.senderPublicKey, "base64"),
        format: "der",
        type: "spki",
      });

      const dataToVerify = Buffer.concat([
        Buffer.from(header.ephemeralPublicKey, "base64"),
        iv,
        authTag,
      ]);

      const signatureValid = verify(
        null,
        dataToVerify,
        senderPubKey,
        Buffer.from(header.signature, "base64")
      );

      if (!signatureValid) {
        throw new Error("Invalid signature - message tampered or wrong sender");
      }

      const sharedSecretAuth = deriveAESKeyForDecryption(
        options.recipientPrivateKey,
        header.ephemeralPublicKey,
        Buffer.from(header.salt, "base64")
      );

      decipher = createDecipheriv("aes-256-gcm", sharedSecretAuth, iv);
      decipher.setAuthTag(authTag);
      break;
  }

  const inputStream = createReadStream(inputPath, { start: dataOffset });
  const outputStream = createWriteStream(outputPath);

  await pipeline(inputStream, decipher, outputStream);

  console.log("✅ File decrypted successfully");
}

// ============================================
// MESSAGE DECRYPTION
// ============================================

/**
 * Decrypt a message (hex string) and return original data
 * @param options - Decryption options
 * @param encryptedHex - Hex-encoded encrypted message
 * @returns Object containing decrypted data and metadata
 * @throws {Error} If decryption fails, password is wrong, signature is invalid, or format is corrupted
 * @example
 * const result = decryptMessage(
 *   { type: "symmetric-password", password: "MyP@ss123" },
 *   "0100a1b2c3d4e5f6..." // hex string
 * );
 * console.log(result.data); // "Secret message" or { key: "value" }
 * console.log(result.metadata?.timestamp); // Unix timestamp if present
 */
function decryptMessage(
  options: MessageDecryptOptions,
  encryptedHex: string
): { data: string | object; metadata?: DecryptMetadata } {
  const buffer = Buffer.from(encryptedHex, "hex");
  let offset = 0;

  // Read version
  const version = buffer[offset];
  if (!version) throw new Error("Missing Version data, can't decrypt");
  validateVersion(version);
  offset += 1;

  const typeFlag = buffer[offset];
  const isString = typeFlag === 0x00;
  offset += 1;

  let decryptedData: string;
  let metadata: DecryptMetadata = {};

  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric decryption");
      }

      // Format: version(1) + typeFlag(1) + salt(16) + iv(12) + tag(16) + encrypted
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

      // Format: version(1) + typeFlag(1) + encryptedKeyLength(2) + encryptedKey + iv(12) + tag(16) + encrypted
      const encryptedKeyLength = buffer.readUInt16BE(offset);
      offset += 2;

      const encryptedKey = buffer.subarray(offset, offset + encryptedKeyLength);
      offset += encryptedKeyLength;

      const ivRSA = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagRSA = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedRSA = buffer.subarray(offset);

      // Convert base64 DER to KeyObject
      const recipientPrivKey = createPrivateKey({
        key: Buffer.from(options.recipientPrivateKey, "base64"),
        format: "der",
        type: "pkcs8",
      });

      const aesKey = privateDecrypt(
        {
          key: recipientPrivKey, // Use KeyObject instead of string
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

      // Format: version(1) + typeFlag(1) + timestampFlag(1) + ephemeralPubKeyLen(2) + ephemeralPubKey + salt(16) + iv(12) + tag(16) + encrypted
      const hasTimestamp = buffer[offset] === 0x01;
      offset += 1;

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

      let decryptedBuffer = Buffer.concat([
        decipherECDH.update(encryptedECDH),
        decipherECDH.final(),
      ]);

      // Extract timestamp if present
      if (hasTimestamp) {
        const decryptedBase64 = decryptedBuffer.toString("utf8");
        const fullBuffer = Buffer.from(decryptedBase64, "base64");

        const timestamp = Number(fullBuffer.readBigUInt64BE(0));
        metadata.timestamp = timestamp;

        // Validate timestamp if requested
        if (options.validateTimestamp !== false || options.strictMode) {
          validateTimestamp(timestamp);
        }

        decryptedData = fullBuffer.subarray(8).toString("utf8");
      } else {
        decryptedData = decryptedBuffer.toString("utf8");
      }
      break;

    case "authenticated-channel":
      if (!options.recipientPrivateKey) {
        throw new Error(
          "Recipient private key required for authenticated channel"
        );
      }
      if (!options.senderPublicKey) {
        throw new Error(
          "Sender public key required for signature verification"
        );
      }

      // Format: version(1) + typeFlag(1) + timestampFlag(1) + ephemeralPubKeyLen(2) + ephemeralPubKey + signatureLen(2) + signature + salt(16) + iv(12) + tag(16) + encrypted
      const hasTimestampAuth = buffer[offset] === 0x01;
      offset += 1;

      const ephemeralKeyLengthAuth = buffer.readUInt16BE(offset);
      offset += 2;

      const ephemeralPublicKeyAuth = buffer.subarray(
        offset,
        offset + ephemeralKeyLengthAuth
      );
      offset += ephemeralKeyLengthAuth;

      const signatureLength = buffer.readUInt16BE(offset);
      offset += 2;

      const signature = buffer.subarray(offset, offset + signatureLength);
      offset += signatureLength;

      const saltAuth = buffer.subarray(offset, offset + 16);
      offset += 16;

      const ivAuth = buffer.subarray(offset, offset + 12);
      offset += 12;

      const tagAuth = buffer.subarray(offset, offset + 16);
      offset += 16;

      const encryptedAuth = buffer.subarray(offset);

      // Verify signature
      const senderPubKey = createPublicKey({
        key: Buffer.from(options.senderPublicKey, "base64"),
        format: "der",
        type: "spki",
      });

      const dataToVerify = Buffer.concat([
        ephemeralPublicKeyAuth,
        ivAuth,
        tagAuth,
      ]);
      const signatureValid = verify(
        null,
        dataToVerify,
        senderPubKey,
        signature
      );

      if (!signatureValid) {
        throw new Error("Invalid signature - message tampered or wrong sender");
      }

      metadata.authenticated = true;

      const sharedSecretAuth = deriveAESKeyForDecryption(
        options.recipientPrivateKey,
        ephemeralPublicKeyAuth.toString("base64"),
        saltAuth
      );

      const decipherAuth = createDecipheriv(
        "aes-256-gcm",
        sharedSecretAuth,
        ivAuth
      );
      decipherAuth.setAuthTag(tagAuth);

      let decryptedBufferAuth = Buffer.concat([
        decipherAuth.update(encryptedAuth),
        decipherAuth.final(),
      ]);

      // Extract timestamp if present
      if (hasTimestampAuth) {
        const decryptedBase64Auth = decryptedBufferAuth.toString("utf8");
        const fullBufferAuth = Buffer.from(decryptedBase64Auth, "base64");

        const timestampAuth = Number(fullBufferAuth.readBigUInt64BE(0));
        metadata.timestamp = timestampAuth;

        // Validate timestamp if requested
        if (options.validateTimestamp !== false || options.strictMode) {
          validateTimestamp(timestampAuth);
        }

        decryptedData = fullBufferAuth.subarray(8).toString("utf8");
      } else {
        decryptedData = decryptedBufferAuth.toString("utf8");
      }
      break;
  }

  const finalData = isString ? decryptedData : JSON.parse(decryptedData);

  return { data: finalData, metadata };
}

// ============================================
// KEY DERIVATION
// ============================================

/**
 * Derive AES key from recipient's private key and ephemeral public key using ECDH
 * @param recipientPrivateKeyStr - Base64-encoded X25519 private key in PKCS8 format
 * @param ephemeralPublicKeyStr - Base64-encoded X25519 ephemeral public key from sender
 * @param salt - 16-byte salt for key derivation
 * @returns 32-byte AES-256 key derived using HKDF
 * @example
 * const aesKey = deriveAESKeyForDecryption(
 *   "MC4CAQAwBQYDK2VuBCIAIE...",
 *   "MCowBQYDK2VuAyEA...",
 *   Buffer.from("a1b2c3d4e5f6...", "hex")
 * );
 * console.log(aesKey.length); // 32 bytes
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
    hkdfSync("sha256", sharedSecret, salt, "secure-channel-aes-key", 32)
  );

  return aesKey;
}

// ============================================
// EXPORTS
// ============
export {
  decrypt,
  decryptFile,
  decryptMessage,
  deriveAESKeyForDecryption,
  validateTimestamp,
  validateVersion,
  // Type exports for consumers
  type SymmetricPasswordDecryptOptions,
  type OpenEnvelopeDecryptOptions,
  type SecureChannelDecryptOptions,
  type AuthenticatedChannelDecryptOptions,
  type MessageDecryptOptions,
  type DecryptResult,
  type MessageDecryptResult,
  type FileDecryptResult,
  type DecryptMetadata,
  type FileHeader,
  type MessageData,
};
