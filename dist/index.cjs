"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  LIBRARY_VERSION: () => LIBRARY_VERSION,
  MAX_MESSAGE_AGE: () => MAX_MESSAGE_AGE,
  MESSAGE_MAX_AGE_MS: () => MESSAGE_MAX_AGE_MS,
  MINIMUM_PASSWORD_LENGTH: () => MINIMUM_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH: () => MIN_PASSWORD_LENGTH,
  VERSION: () => VERSION,
  decrypt: () => decrypt,
  decryptFile: () => decryptFile,
  decryptMessage: () => decryptMessage,
  deriveAESKeyForDecryption: () => deriveAESKeyForDecryption,
  deriveAESKeyForEncryption: () => deriveAESKeyForEncryption,
  encrypt: () => encrypt,
  encryptFileStreaming: () => encryptFileStreaming,
  encryptMessage: () => encryptMessage,
  hash: () => hash_exports,
  keys: () => keys_exports,
  otp: () => otp_exports,
  password: () => password_exports,
  signature: () => signature_exports,
  uuid: () => uuid_exports,
  validatePassword: () => validatePassword,
  validatePrivateKey: () => validatePrivateKey,
  validatePublicKey: () => validatePublicKey,
  validateTimestamp: () => validateTimestamp,
  validateVersion: () => validateVersion
});
module.exports = __toCommonJS(index_exports);

// src/crypto/encrypt.ts
var import_fs = require("fs");
var import_promises = require("fs/promises");
var import_crypto = require("crypto");
var import_promises2 = require("stream/promises");
var import_os = require("os");
var import_path = require("path");
var VERSION = 1;
var MIN_PASSWORD_LENGTH = 12;
var MESSAGE_MAX_AGE_MS = 5 * 60 * 1e3;
function validatePassword(password, strictMode = false) {
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
      "\u26A0\uFE0F Weak password: consider using uppercase, lowercase, numbers, and special characters"
    );
  }
}
function validatePublicKey(keyStr, expectedType) {
  try {
    const keyBuffer = Buffer.from(keyStr, "base64");
    const key = (0, import_crypto.createPublicKey)({
      key: keyBuffer,
      format: "der",
      type: "spki"
    });
    if (key.asymmetricKeyType !== expectedType) {
      throw new Error(
        `Expected ${expectedType} key, got ${key.asymmetricKeyType}`
      );
    }
  } catch (err) {
    throw new Error(`Invalid ${expectedType} public key: ${err.message}`);
  }
}
function validatePrivateKey(keyStr, expectedType) {
  try {
    const keyBuffer = Buffer.from(keyStr, "base64");
    const key = (0, import_crypto.createPrivateKey)({
      key: keyBuffer,
      format: "der",
      type: "pkcs8"
    });
    if (key.asymmetricKeyType !== expectedType) {
      throw new Error(
        `Expected ${expectedType} key, got ${key.asymmetricKeyType}`
      );
    }
  } catch (err) {
    throw new Error(`Invalid ${expectedType} private key: ${err.message}`);
  }
}
async function secureDelete(filePath) {
  try {
    await (0, import_promises.unlink)(filePath);
  } catch (err) {
    console.error(`\u26A0\uFE0F Failed to delete temp file ${filePath}:`, err.message);
  }
}
function createTimestampBuffer() {
  const timestamp = Date.now();
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestamp), 0);
  return buf;
}
async function encrypt(options, data, inputPath, outputPath) {
  if (!data && !inputPath) {
    throw new Error("No data to encrypt");
  }
  if (options.strictMode) {
    console.log("\u{1F512} Strict mode enabled - all security checks active");
  }
  const isFile = inputPath && outputPath;
  if (isFile) {
    await encryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    let messageData;
    if (Buffer.isBuffer(data)) {
      messageData = data.toString("utf8");
    } else if (typeof data === "string") {
      messageData = data;
    } else {
      messageData = data;
    }
    const encrypted = encryptMessage(options, messageData);
    return { type: "message", data: encrypted };
  }
}
async function encryptFile(options, inputPath, outputPath) {
  await encryptFileStreaming(options, inputPath, outputPath);
}
async function encryptFileStreaming(options, inputPath, outputPath) {
  const aesKey = (0, import_crypto.randomBytes)(32);
  const iv = (0, import_crypto.randomBytes)(12);
  const tempPath = (0, import_path.join)(
    (0, import_os.tmpdir)(),
    `temp-encrypt-${Date.now()}-${(0, import_crypto.randomBytes)(4).toString("hex")}.tmp`
  );
  try {
    const tempStream = (0, import_fs.createWriteStream)(tempPath);
    const inputStream = (0, import_fs.createReadStream)(inputPath);
    let header;
    switch (options.type) {
      case "symmetric-password":
        validatePassword(options.password, options.strictMode);
        const salt = (0, import_crypto.randomBytes)(16);
        const key = (0, import_crypto.scryptSync)(options.password, salt, 32);
        const cipherSymmetric = (0, import_crypto.createCipheriv)("aes-256-gcm", key, iv);
        await (0, import_promises2.pipeline)(inputStream, cipherSymmetric, tempStream);
        const authTagSymmetric = cipherSymmetric.getAuthTag();
        header = {
          version: VERSION,
          iv: iv.toString("base64"),
          authTag: authTagSymmetric.toString("base64"),
          salt: salt.toString("base64")
        };
        break;
      case "sealEnvelope":
        validatePublicKey(options.recipientPublicKey, "rsa");
        const cipherSeal = (0, import_crypto.createCipheriv)("aes-256-gcm", aesKey, iv);
        await (0, import_promises2.pipeline)(inputStream, cipherSeal, tempStream);
        const authTagSeal = cipherSeal.getAuthTag();
        const recipientPubKey = (0, import_crypto.createPublicKey)({
          key: Buffer.from(options.recipientPublicKey, "base64"),
          format: "der",
          type: "spki"
        });
        const encryptedAESKey = (0, import_crypto.publicEncrypt)(
          {
            key: recipientPubKey,
            // Use KeyObject instead of string
            padding: import_crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
          },
          aesKey
        );
        header = {
          version: VERSION,
          encryptedKey: encryptedAESKey.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagSeal.toString("base64")
        };
        break;
      case "secure-channel":
        validatePublicKey(options.recipientPublicKey, "x25519");
        const ephemeralData = deriveAESKeyForEncryption(
          options.recipientPublicKey
        );
        const cipherECDH = (0, import_crypto.createCipheriv)(
          "aes-256-gcm",
          ephemeralData.aesKey,
          iv
        );
        await (0, import_promises2.pipeline)(inputStream, cipherECDH, tempStream);
        const authTagECDH = cipherECDH.getAuthTag();
        header = {
          version: VERSION,
          ephemeralPublicKey: ephemeralData.ephemeralPublicKey,
          salt: ephemeralData.salt.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagECDH.toString("base64")
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
        const cipherAuth = (0, import_crypto.createCipheriv)(
          "aes-256-gcm",
          ephemeralAuthData.aesKey,
          iv
        );
        await (0, import_promises2.pipeline)(inputStream, cipherAuth, tempStream);
        const authTagAuth = cipherAuth.getAuthTag();
        const senderPrivKey = (0, import_crypto.createPrivateKey)({
          key: Buffer.from(options.senderPrivateKey, "base64"),
          format: "der",
          type: "pkcs8"
        });
        const dataToSign = Buffer.concat([
          Buffer.from(ephemeralAuthData.ephemeralPublicKey, "base64"),
          iv,
          authTagAuth
        ]);
        const signature = (0, import_crypto.sign)(null, dataToSign, senderPrivKey);
        header = {
          version: VERSION,
          ephemeralPublicKey: ephemeralAuthData.ephemeralPublicKey,
          salt: ephemeralAuthData.salt.toString("base64"),
          signature: signature.toString("base64"),
          iv: iv.toString("base64"),
          authTag: authTagAuth.toString("base64")
        };
        if (options.includeTimestamp !== false) {
          header.timestamp = Date.now();
        }
        break;
    }
    const headerJson = Buffer.from(JSON.stringify(header), "utf8");
    const headerLengthBuf = Buffer.alloc(4);
    headerLengthBuf.writeUInt32BE(headerJson.length, 0);
    const outputStream = (0, import_fs.createWriteStream)(outputPath);
    outputStream.write(headerLengthBuf);
    outputStream.write(headerJson);
    const tempReadStream = (0, import_fs.createReadStream)(tempPath);
    await (0, import_promises2.pipeline)(tempReadStream, outputStream);
    console.log("\u2705 File encrypted successfully");
  } finally {
    await secureDelete(tempPath);
  }
}
function encryptMessage(options, data) {
  const isString = typeof data === "string";
  const stringData = isString ? data : JSON.stringify(data);
  const versionByte = Buffer.from([VERSION]);
  const typeFlag = Buffer.from([isString ? 0 : 1]);
  const iv = (0, import_crypto.randomBytes)(12);
  const aesKey = (0, import_crypto.randomBytes)(32);
  switch (options.type) {
    case "symmetric-password":
      validatePassword(options.password, options.strictMode);
      const salt = (0, import_crypto.randomBytes)(16);
      const key = (0, import_crypto.scryptSync)(options.password, salt, 32);
      const cipher = (0, import_crypto.createCipheriv)("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([
        cipher.update(stringData, "utf8"),
        cipher.final()
      ]);
      const tag = cipher.getAuthTag();
      return Buffer.concat([
        versionByte,
        typeFlag,
        salt,
        iv,
        tag,
        encrypted
      ]).toString("hex");
    case "sealEnvelope":
      validatePublicKey(options.recipientPublicKey, "rsa");
      const cipherSeal = (0, import_crypto.createCipheriv)("aes-256-gcm", aesKey, iv);
      const encryptedSeal = Buffer.concat([
        cipherSeal.update(stringData, "utf8"),
        cipherSeal.final()
      ]);
      const tagSeal = cipherSeal.getAuthTag();
      const recipientPubKey = (0, import_crypto.createPublicKey)({
        key: Buffer.from(options.recipientPublicKey, "base64"),
        format: "der",
        type: "spki"
      });
      const encryptedKey = (0, import_crypto.publicEncrypt)(
        {
          key: recipientPubKey,
          // Use KeyObject instead of string
          padding: import_crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
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
        encryptedSeal
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
          Buffer.from(stringData, "utf8")
        ]).toString("base64");
        hasTimestamp = true;
      }
      const cipherECDH = (0, import_crypto.createCipheriv)(
        "aes-256-gcm",
        ephemeralData.aesKey,
        iv
      );
      const encryptedECDH = Buffer.concat([
        cipherECDH.update(dataToEncrypt, "utf8"),
        cipherECDH.final()
      ]);
      const tagECDH = cipherECDH.getAuthTag();
      const ephemeralKeyBuffer = Buffer.from(
        ephemeralData.ephemeralPublicKey,
        "base64"
      );
      const ephemeralKeyLenBuf = Buffer.alloc(2);
      ephemeralKeyLenBuf.writeUInt16BE(ephemeralKeyBuffer.length, 0);
      const timestampFlag = Buffer.from([hasTimestamp ? 1 : 0]);
      return Buffer.concat([
        versionByte,
        typeFlag,
        timestampFlag,
        ephemeralKeyLenBuf,
        ephemeralKeyBuffer,
        ephemeralData.salt,
        iv,
        tagECDH,
        encryptedECDH
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
          Buffer.from(stringData, "utf8")
        ]).toString("base64");
        hasTimestampAuth = true;
      }
      const cipherAuth = (0, import_crypto.createCipheriv)(
        "aes-256-gcm",
        ephemeralAuthData.aesKey,
        iv
      );
      const encryptedAuth = Buffer.concat([
        cipherAuth.update(dataToEncryptAuth, "utf8"),
        cipherAuth.final()
      ]);
      const tagAuth = cipherAuth.getAuthTag();
      const senderPrivKey = (0, import_crypto.createPrivateKey)({
        key: Buffer.from(options.senderPrivateKey, "base64"),
        format: "der",
        type: "pkcs8"
      });
      const ephemeralKeyBufferAuth = Buffer.from(
        ephemeralAuthData.ephemeralPublicKey,
        "base64"
      );
      const dataToSign = Buffer.concat([ephemeralKeyBufferAuth, iv, tagAuth]);
      const signature = (0, import_crypto.sign)(null, dataToSign, senderPrivKey);
      const ephemeralKeyLenBufAuth = Buffer.alloc(2);
      ephemeralKeyLenBufAuth.writeUInt16BE(ephemeralKeyBufferAuth.length, 0);
      const signatureLenBuf = Buffer.alloc(2);
      signatureLenBuf.writeUInt16BE(signature.length, 0);
      const timestampFlagAuth = Buffer.from([hasTimestampAuth ? 1 : 0]);
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
        encryptedAuth
      ]).toString("hex");
  }
}
function deriveAESKeyForEncryption(recipientPublicKeyStr) {
  const { publicKey, privateKey } = (0, import_crypto.generateKeyPairSync)("x25519");
  const recipientPublicKey = (0, import_crypto.createPublicKey)({
    key: Buffer.from(recipientPublicKeyStr, "base64"),
    format: "der",
    type: "spki"
  });
  const salt = (0, import_crypto.randomBytes)(16);
  const sharedSecret = (0, import_crypto.diffieHellman)({
    privateKey,
    publicKey: recipientPublicKey
  });
  const aesKey = Buffer.from(
    (0, import_crypto.hkdfSync)("sha256", sharedSecret, salt, "secure-channel-aes-key", 32)
  );
  return {
    aesKey,
    ephemeralPublicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    ephemeralPrivateKey: privateKey,
    salt
  };
}

// src/password/index.ts
var password_exports = {};
__export(password_exports, {
  generatePassword: () => generatePassword,
  hashPassword: () => hashPassword,
  verifyPassword: () => verifyPassword
});

// src/password/generate.ts
var import_crypto2 = require("crypto");
var charsetMap = {
  letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?"
};
function generatePassword(lengthOrOptions) {
  let length = 16;
  let letters = true;
  let numbers = true;
  let symbols = true;
  if (typeof lengthOrOptions === "number") {
    length = lengthOrOptions;
  } else if (typeof lengthOrOptions === "object") {
    length = lengthOrOptions.length ?? 16;
    letters = lengthOrOptions.letters ?? true;
    numbers = lengthOrOptions.numbers ?? true;
    symbols = lengthOrOptions.symbols ?? true;
  }
  let charset = "";
  if (letters) charset += charsetMap.letters;
  if (numbers) charset += charsetMap.numbers;
  if (symbols) charset += charsetMap.symbols;
  if (charset.length === 0) {
    charset = Object.values(charsetMap).join("");
  }
  if (length < 1 || length > 1024) {
    throw new Error("Length must be between 1 and 1024");
  }
  const bytes = (0, import_crypto2.randomBytes)(length);
  const password = Array.from(
    bytes,
    (byte) => charset[byte % charset.length]
  ).join("");
  return password;
}

// src/password/hash.ts
var import_crypto3 = require("crypto");
var import_util = require("util");
var scryptAsync = (0, import_util.promisify)(import_crypto3.scrypt);
async function hashPassword(password) {
  const salt = (0, import_crypto3.randomBytes)(16);
  const derivedKey = await scryptAsync(password, salt, 64);
  const saltBase64 = salt.toString("base64");
  const hashBase64 = derivedKey.toString("base64");
  return `scrypt$16$${saltBase64}$${hashBase64}`;
}

// src/password/verify.ts
var import_crypto4 = require("crypto");
var import_util2 = require("util");
var scryptAsync2 = (0, import_util2.promisify)(import_crypto4.scrypt);
async function scryptTyped(password, salt, keylen) {
  const result = await scryptAsync2(password, salt, keylen);
  if (!result) throw new Error("Scrypt derivation failed");
  return result;
}
async function verifyPassword(password, storedHash) {
  const [method, saltLengthStr, saltBase64, hashBase64] = storedHash.split("$");
  if (method !== "scrypt") throw new Error("Unsupported hash method");
  if (!saltBase64 || !hashBase64 || !saltLengthStr)
    throw new Error("Invalid stored hash format");
  const salt = Buffer.from(saltBase64, "base64");
  const derivedKey = await scryptTyped(password, salt, 64);
  const hashBuffer = Buffer.from(hashBase64, "base64");
  if (derivedKey.length !== hashBuffer.length) return false;
  let diff = 0;
  for (let i = 0; i < derivedKey.length; i++) {
    diff |= derivedKey[i] ^ hashBuffer[i];
  }
  return diff === 0;
}

// src/uuid/index.ts
var uuid_exports = {};
__export(uuid_exports, {
  generateUUID: () => generateUUID
});

// src/uuid/generate.ts
var import_crypto5 = require("crypto");
function generateUUID() {
  return (0, import_crypto5.randomUUID)();
}

// src/signature/index.ts
var signature_exports = {};
__export(signature_exports, {
  Signer: () => Signer,
  default: () => Signer,
  envelope: () => envelope,
  openEnvelope: () => openEnvelope,
  sign: () => sign2,
  verify: () => verify
});

// src/signature/sign.ts
var import_crypto6 = require("crypto");

// src/signature/serialize.ts
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(
    (key) => JSON.stringify(key) + ":" + canonicalStringify(obj[key])
  );
  return "{" + pairs.join(",") + "}";
}
function serialize(data, strategy, fields) {
  switch (strategy) {
    case "canonical":
      return canonicalStringify(data);
    case "raw":
      return typeof data === "string" ? data : JSON.stringify(data);
    case "selective":
      if (!fields || fields.length === 0) {
        throw new Error("Selective strategy requires fields parameter");
      }
      const selected = {};
      for (const field of fields) {
        if (field in data) {
          selected[field] = data[field];
        }
      }
      return canonicalStringify(selected);
    default:
      throw new Error(`Unknown strategy: ${strategy}`);
  }
}

// src/signature/sign.ts
function parsePrivateKey(key) {
  const keyObject = (0, import_crypto6.createPrivateKey)({
    key: Buffer.from(key, "base64"),
    format: "der",
    type: "pkcs8"
  });
  if (keyObject.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected ed25519 key, got ${keyObject.asymmetricKeyType}`);
  }
  return keyObject;
}
function sign2(data, privateKey, options) {
  const keyObject = parsePrivateKey(privateKey);
  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );
  return (0, import_crypto6.sign)(
    null,
    // ✅ Ed25519 requires null
    Buffer.from(serialized),
    keyObject
  ).toString(options?.encoding ?? "base64");
}

// src/signature/verify.ts
var import_crypto7 = require("crypto");
function parsePublicKey(key) {
  const keyObject = (0, import_crypto7.createPublicKey)({
    key: Buffer.from(key, "base64"),
    format: "der",
    type: "spki"
  });
  if (keyObject.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected ed25519 key, got ${keyObject.asymmetricKeyType}`);
  }
  return keyObject;
}
function verify(data, signature, publicKey, options) {
  const keyObject = parsePublicKey(publicKey);
  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );
  return (0, import_crypto7.verify)(
    null,
    // ✅ required for ed25519
    Buffer.from(serialized),
    keyObject,
    Buffer.from(signature, options?.encoding ?? "base64")
  );
}

// src/signature/index.ts
var Signer = class _Signer {
  /**
   * Creates a new Signer instance with optional default options.
   *
   * @param defaultOptions - Partial default options to override
   *  serialization strategy, fields, algorithm, encoding, or preHash.
   */
  constructor(defaultOptions) {
    this.defaultOptions = {
      strategy: defaultOptions?.strategy ?? "canonical",
      fields: defaultOptions?.fields ?? [],
      algorithm: defaultOptions?.algorithm ?? "SHA256",
      encoding: defaultOptions?.encoding ?? "base64",
      preHash: defaultOptions?.preHash ?? false
    };
  }
  /**
   * Sign data with a private key (static method).
   *
   * @param data - The data to sign.
   * @param privateKey - The private key to use for signing.
   * @param options - Optional signing options.
   * @returns The digital signature as a string.
   *
   * @example
   * ```ts
   * const signature = Signer.sign({ message: "Hello" }, privateKey);
   * ```
   */
  static sign(data, privateKey, options) {
    const opts = {
      strategy: options?.strategy ?? "canonical",
      fields: options?.fields ?? [],
      encoding: options?.encoding ?? "base64"
    };
    const signOpts = {
      fields: opts.fields,
      encoding: opts.encoding
    };
    if (opts.strategy === "canonical") {
      signOpts.strategy = "canonical";
    }
    return sign2(data, privateKey, signOpts);
  }
  /**
   * Verify a signature with a public key (static method).
   *
   * @param data - The original data.
   * @param signature - The signature to verify.
   * @param publicKey - The public key corresponding to the signer.
   * @param options - Optional verification options.
   * @returns `true` if the signature is valid, `false` otherwise.
   *
   * @example
   * ```ts
   * const isValid = Signer.verify({ message: "Hello" }, signature, publicKey);
   * ```
   */
  static verify(data, signature, publicKey, options) {
    const opts = {
      strategy: options?.strategy ?? "canonical",
      fields: options?.fields ?? [],
      encoding: options?.encoding ?? "base64"
    };
    const verifyOpts = {
      fields: opts.fields,
      encoding: opts.encoding
    };
    if (opts.strategy === "canonical") {
      verifyOpts.strategy = "canonical";
    }
    return verify(data, signature, publicKey, verifyOpts);
  }
  /**
   * Create a signed envelope containing the data and its signature (static method).
   *
   * @param data - The data to include in the envelope.
   * @param privateKey - The private key for signing.
   * @param options - Optional signing options.
   * @returns An object containing `{ data, signature }`.
   *
   * @example
   * ```ts
   * const envelope = Signer.envelope({ message: "Hello" }, privateKey);
   * ```
   */
  static envelope(data, privateKey, options) {
    return {
      data,
      signature: _Signer.sign(data, privateKey, options)
    };
  }
  /**
   * Verify and extract data from a signed envelope (static method).
   *
   * @param envelope - The envelope object `{ data, signature }`.
   * @param publicKey - The public key to verify the signature.
   * @param options - Optional verification options.
   * @returns An object `{ valid, data }` indicating whether the signature is valid.
   *
   * @example
   * ```ts
   * const result = Signer.openEnvelope(envelope, publicKey);
   * ```
   */
  static openEnvelope(envelope2, publicKey, options) {
    const valid = _Signer.verify(
      envelope2.data,
      envelope2.signature,
      publicKey,
      options
    );
    return { valid, data: envelope2.data };
  }
  /**
   * Sign data with a private key (instance method).
   *
   * @param data - The data to sign.
   * @param privateKey - The private key to use for signing.
   * @param options - Optional signing options.
   * @returns The digital signature as a string.
   *
   * @example
   * ```ts
   * const signer = new Signer();
   * const signature = signer.sign({ message: "Hello" }, privateKey);
   * ```
   */
  sign(data, privateKey, options) {
    const opts = { ...this.defaultOptions, ...options };
    const signOpts = {
      fields: opts.fields,
      encoding: opts.encoding
    };
    if (opts.strategy === "canonical") {
      signOpts.strategy = "canonical";
    }
    return sign2(data, privateKey, signOpts);
  }
  /**
   * Verify a signature with a public key (instance method).
   *
   * @param data - The original data.
   * @param signature - The signature to verify.
   * @param publicKey - The public key corresponding to the signer.
   * @param options - Optional verification options.
   * @returns `true` if the signature is valid, `false` otherwise.
   *
   * @example
   * ```ts
   * const isValid = signer.verify({ message: "Hello" }, signature, publicKey);
   * ```
   */
  verify(data, signature, publicKey, options) {
    const opts = { ...this.defaultOptions, ...options };
    const verifyOpts = {
      fields: opts.fields,
      encoding: opts.encoding
    };
    if (opts.strategy === "canonical") {
      verifyOpts.strategy = "canonical";
    }
    return verify(data, signature, publicKey, verifyOpts);
  }
  /**
   * Create a signed envelope containing the data and its signature (instance method).
   *
   * @param data - The data to include in the envelope.
   * @param privateKey - The private key for signing.
   * @param options - Optional signing options.
   * @returns An object containing `{ data, signature }`.
   *
   * @example
   * ```ts
   * const envelope = signer.envelope({ message: "Hello" }, privateKey);
   * ```
   */
  envelope(data, privateKey, options) {
    return {
      data,
      signature: this.sign(data, privateKey, options)
    };
  }
  /**
   * Verify and extract data from a signed envelope (instance method).
   *
   * @param envelope - The envelope object `{ data, signature }`.
   * @param publicKey - The public key to verify the signature.
   * @param options - Optional verification options.
   * @returns An object `{ valid, data }` indicating whether the signature is valid.
   *
   * @example
   * ```ts
   * const result = signer.openEnvelope(envelope, publicKey);
   * ```
   */
  openEnvelope(envelope2, publicKey, options) {
    const valid = this.verify(
      envelope2.data,
      envelope2.signature,
      publicKey,
      options
    );
    return { valid, data: envelope2.data };
  }
};
var defaultSigner = new Signer();
var envelope = defaultSigner.envelope.bind(defaultSigner);
var openEnvelope = defaultSigner.openEnvelope.bind(defaultSigner);

// src/hash/index.ts
var hash_exports = {};
__export(hash_exports, {
  hash: () => hash,
  hashHmac: () => hashHmac,
  verifyHmac: () => verifyHmac
});

// src/hash/hash.ts
var import_crypto8 = require("crypto");
function hash(data) {
  const hash2 = (0, import_crypto8.createHash)("sha256");
  hash2.update(data);
  return hash2.digest("hex");
}

// src/hash/hashHmac.ts
var import_crypto9 = require("crypto");
function hashHmac(secret, data) {
  return (0, import_crypto9.createHmac)("sha256", secret).update(data).digest("hex");
}

// src/hash/verifyHmac.ts
var import_crypto10 = require("crypto");
function verifyHmac(secret, data, expectedHex) {
  const actual = (0, import_crypto10.createHmac)("sha256", secret).update(data).digest();
  const expected = Buffer.from(expectedHex, "hex");
  if (actual.length !== expected.length) {
    return false;
  }
  return (0, import_crypto10.timingSafeEqual)(actual, expected);
}

// src/keys/index.ts
var keys_exports = {};
__export(keys_exports, {
  Key: () => Key,
  generateECDHKeyPair: () => generateECDHKeyPair,
  generateRSAKeyPair: () => generateRSAKeyPair
});

// src/keys/rsa.ts
var import_crypto11 = require("crypto");
function generateRSAKeyPair() {
  return new Promise((resolve, reject) => {
    (0, import_crypto11.generateKeyPair)(
      "rsa",
      {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: "spki",
          format: "der"
          // Changed from "pem" to "der"
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "der"
          // Changed from "pem" to "der"
        }
      },
      (err, publicKey, privateKey) => {
        if (err) return reject(err);
        resolve({
          publicKey: publicKey.toString("base64"),
          privateKey: privateKey.toString("base64")
        });
      }
    );
  });
}

// src/keys/ed25519.ts
var import_crypto12 = require("crypto");
function generateEd25519KeyPair() {
  const { publicKey, privateKey } = (0, import_crypto12.generateKeyPairSync)("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der"
    }
  });
  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64")
  };
}

// src/keys/x25519.ts
var import_crypto13 = require("crypto");
function generateX25519KeyPair() {
  const { publicKey, privateKey } = (0, import_crypto13.generateKeyPairSync)("x25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der"
    }
  });
  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64")
  };
}

// src/keys/authenticated.ts
function generateAuthenticatedKeySet() {
  return {
    encryption: generateX25519KeyPair(),
    signing: generateEd25519KeyPair()
  };
}

// src/keys/ecdh.ts
var import_crypto14 = require("crypto");
function generateECDHKeyPair() {
  const { publicKey, privateKey } = (0, import_crypto14.generateKeyPairSync)("x25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")
  };
}

// src/keys/index.ts
var Key = class _Key {
  /**
   * Generates a new Key instance for the specified `keyType`.
   *
   * @param key - The type of key to generate:
   *   - `"seal"`: RSA key pair for encryption/signing
   *   - `"sign"`: Ed25519 key pair for signing
   *   - `"secure-channel"`: X25519 key pair for ECDH (secure channel)
   *   - `"authenticated-channel"`: Combined X25519 + Ed25519 key pair
   *
   * @returns A Promise that resolves to a `Key` instance with the generated keys.
   *
   * @example
   * ```ts
   * import { Key } from "./key";
   *
   * async function main() {
   *   const sealKey = await Key.generate("seal");
   *   console.log(sealKey.publicKey);
   *   console.log(sealKey.privateKey);
   *
   *   const authKey = await Key.generate("authenticated-channel");
   *   console.log(authKey.publicKey);        // Encryption key
   *   console.log(authKey.signingPublicKey); // Signing key
   * }
   *
   * main();
   * ```
   */
  static async generate(key) {
    const k = new _Key();
    switch (key) {
      case "authenticated-channel": {
        const key2 = generateAuthenticatedKeySet();
        k.publicKey = key2.encryption.publicKey;
        k.privateKey = key2.encryption.privateKey;
        k.signingPublicKey = key2.signing.publicKey;
        k.signingPrivateKey = key2.signing.privateKey;
        break;
      }
      case "secure-channel": {
        const { publicKey, privateKey } = generateX25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }
      case "seal": {
        const { publicKey, privateKey } = await generateRSAKeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }
      case "sign": {
        const { publicKey, privateKey } = generateEd25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }
      default:
        throw new Error(`Unknown key type: ${key}`);
    }
    return k;
  }
};

// src/otp/index.ts
var otp_exports = {};
__export(otp_exports, {
  generateOTP: () => generateOTP,
  generateTOTP: () => generateTOTP
});

// src/otp/totp.ts
var import_crypto15 = require("crypto");
function base32ToBuffer(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let bytes = [];
  base32 = base32.replace(/=+$/, "").toUpperCase();
  for (const char of base32) {
    const val = alphabet.indexOf(char);
    bits += val.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}
function generateTOTP(secret, digits = 6, period = 30, timestamp = Date.now()) {
  const key = base32ToBuffer(secret);
  let counter = Math.floor(timestamp / 1e3 / period);
  const buffer = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    buffer[i] = counter & 255;
    counter >>= 8;
  }
  const hmac = (0, import_crypto15.createHmac)("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 15;
  const code = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

// src/otp/otp.ts
var import_crypto16 = require("crypto");
function generateOTP(length = 6) {
  const max = 10 ** length;
  const randomNumber = parseInt((0, import_crypto16.randomBytes)(4).toString("hex"), 16) % max;
  return randomNumber.toString().padStart(length, "0");
}

// src/crypto/decrypt.ts
var import_fs2 = require("fs");
var import_crypto17 = require("crypto");
var import_promises3 = require("stream/promises");
function validateTimestamp(timestamp, maxAge = MESSAGE_MAX_AGE_MS) {
  const now = Date.now();
  const age = now - timestamp;
  if (age < 0) {
    throw new Error(
      "Message timestamp is in the future - possible clock skew or attack"
    );
  }
  if (age > maxAge) {
    throw new Error(
      `Message expired (age: ${Math.floor(age / 1e3)}s, max: ${Math.floor(
        maxAge / 1e3
      )}s) - possible replay attack`
    );
  }
}
function validateVersion(version) {
  if (version !== VERSION) {
    throw new Error(
      `Unsupported format version: ${version} (expected: ${VERSION})`
    );
  }
}
async function decrypt(options, data, inputPath, outputPath) {
  if (!data && !inputPath) {
    throw new Error("No data to decrypt");
  }
  if (options.strictMode) {
    console.log("\u{1F512} Strict mode enabled - all security checks active");
  }
  const isFile = inputPath && outputPath;
  if (isFile) {
    await decryptFile(options, inputPath, outputPath);
    return { type: "file", outputPath };
  } else {
    const encryptedHex = typeof data === "string" ? data : data.toString("hex");
    const result = decryptMessage(options, encryptedHex);
    return {
      type: "message",
      data: result.data,
      metadata: result.metadata
    };
  }
}
async function decryptFile(options, inputPath, outputPath) {
  async function readFileHeader(filePath) {
    return new Promise((resolve, reject) => {
      const stream = (0, import_fs2.createReadStream)(filePath, { start: 0 });
      const chunks = [];
      let bytesRead = 0;
      let headerLength = 0;
      let headerBuffer = null;
      stream.on("data", (chunk) => {
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
        const header2 = JSON.parse(headerJson);
        validateVersion(header2.version);
        const encryptedDataOffset2 = 4 + headerLength;
        resolve({ header: header2, encryptedDataOffset: encryptedDataOffset2 });
      });
      stream.on("error", reject);
    });
  }
  const { header, encryptedDataOffset } = await readFileHeader(inputPath);
  if (header.timestamp) {
    const shouldValidate = options.type === "secure-channel" && options.validateTimestamp !== false || options.type === "authenticated-channel" && options.validateTimestamp !== false || options.strictMode;
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
async function decryptFileStreaming(options, inputPath, outputPath, header, dataOffset) {
  const iv = Buffer.from(header.iv, "base64");
  const authTag = Buffer.from(header.authTag, "base64");
  let decipher;
  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric decryption");
      }
      if (!header.salt) {
        throw new Error("Salt missing from encrypted file");
      }
      const salt = Buffer.from(header.salt, "base64");
      const key = (0, import_crypto17.scryptSync)(options.password, salt, 32);
      decipher = (0, import_crypto17.createDecipheriv)("aes-256-gcm", key, iv);
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
      const recipientPrivKey = (0, import_crypto17.createPrivateKey)({
        key: Buffer.from(options.recipientPrivateKey, "base64"),
        format: "der",
        type: "pkcs8"
      });
      const aesKey = (0, import_crypto17.privateDecrypt)(
        {
          key: recipientPrivKey,
          // Use KeyObject instead of string
          padding: import_crypto17.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        },
        encryptedAESKey
      );
      decipher = (0, import_crypto17.createDecipheriv)("aes-256-gcm", aesKey, iv);
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
      decipher = (0, import_crypto17.createDecipheriv)("aes-256-gcm", sharedSecret, iv);
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
      const senderPubKey = (0, import_crypto17.createPublicKey)({
        key: Buffer.from(options.senderPublicKey, "base64"),
        format: "der",
        type: "spki"
      });
      const dataToVerify = Buffer.concat([
        Buffer.from(header.ephemeralPublicKey, "base64"),
        iv,
        authTag
      ]);
      const signatureValid = (0, import_crypto17.verify)(
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
      decipher = (0, import_crypto17.createDecipheriv)("aes-256-gcm", sharedSecretAuth, iv);
      decipher.setAuthTag(authTag);
      break;
  }
  const inputStream = (0, import_fs2.createReadStream)(inputPath, { start: dataOffset });
  const outputStream = (0, import_fs2.createWriteStream)(outputPath);
  await (0, import_promises3.pipeline)(inputStream, decipher, outputStream);
  console.log("\u2705 File decrypted successfully");
}
function decryptMessage(options, encryptedHex) {
  const buffer = Buffer.from(encryptedHex, "hex");
  let offset = 0;
  const version = buffer[offset];
  if (!version) throw new Error("Missing Version data, can't decrypt");
  validateVersion(version);
  offset += 1;
  const typeFlag = buffer[offset];
  const isString = typeFlag === 0;
  offset += 1;
  let decryptedData;
  let metadata = {};
  switch (options.type) {
    case "symmetric-password":
      if (!options.password) {
        throw new Error("Password required for symmetric decryption");
      }
      const salt = buffer.subarray(offset, offset + 16);
      offset += 16;
      const ivSymmetric = buffer.subarray(offset, offset + 12);
      offset += 12;
      const tagSymmetric = buffer.subarray(offset, offset + 16);
      offset += 16;
      const encryptedSymmetric = buffer.subarray(offset);
      const key = (0, import_crypto17.scryptSync)(options.password, salt, 32);
      const decipherSymmetric = (0, import_crypto17.createDecipheriv)(
        "aes-256-gcm",
        key,
        ivSymmetric
      );
      decipherSymmetric.setAuthTag(tagSymmetric);
      decryptedData = Buffer.concat([
        decipherSymmetric.update(encryptedSymmetric),
        decipherSymmetric.final()
      ]).toString("utf8");
      break;
    case "openEnvelope":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for decryption");
      }
      const encryptedKeyLength = buffer.readUInt16BE(offset);
      offset += 2;
      const encryptedKey = buffer.subarray(offset, offset + encryptedKeyLength);
      offset += encryptedKeyLength;
      const ivRSA = buffer.subarray(offset, offset + 12);
      offset += 12;
      const tagRSA = buffer.subarray(offset, offset + 16);
      offset += 16;
      const encryptedRSA = buffer.subarray(offset);
      const recipientPrivKey = (0, import_crypto17.createPrivateKey)({
        key: Buffer.from(options.recipientPrivateKey, "base64"),
        format: "der",
        type: "pkcs8"
      });
      const aesKey = (0, import_crypto17.privateDecrypt)(
        {
          key: recipientPrivKey,
          // Use KeyObject instead of string
          padding: import_crypto17.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        },
        encryptedKey
      );
      const decipherRSA = (0, import_crypto17.createDecipheriv)("aes-256-gcm", aesKey, ivRSA);
      decipherRSA.setAuthTag(tagRSA);
      decryptedData = Buffer.concat([
        decipherRSA.update(encryptedRSA),
        decipherRSA.final()
      ]).toString("utf8");
      break;
    case "secure-channel":
      if (!options.recipientPrivateKey) {
        throw new Error("Recipient private key required for secure channel");
      }
      const hasTimestamp = buffer[offset] === 1;
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
      const decipherECDH = (0, import_crypto17.createDecipheriv)(
        "aes-256-gcm",
        sharedSecret,
        ivECDH
      );
      decipherECDH.setAuthTag(tagECDH);
      let decryptedBuffer = Buffer.concat([
        decipherECDH.update(encryptedECDH),
        decipherECDH.final()
      ]);
      if (hasTimestamp) {
        const decryptedBase64 = decryptedBuffer.toString("utf8");
        const fullBuffer = Buffer.from(decryptedBase64, "base64");
        const timestamp = Number(fullBuffer.readBigUInt64BE(0));
        metadata.timestamp = timestamp;
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
      const hasTimestampAuth = buffer[offset] === 1;
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
      const senderPubKey = (0, import_crypto17.createPublicKey)({
        key: Buffer.from(options.senderPublicKey, "base64"),
        format: "der",
        type: "spki"
      });
      const dataToVerify = Buffer.concat([
        ephemeralPublicKeyAuth,
        ivAuth,
        tagAuth
      ]);
      const signatureValid = (0, import_crypto17.verify)(
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
      const decipherAuth = (0, import_crypto17.createDecipheriv)(
        "aes-256-gcm",
        sharedSecretAuth,
        ivAuth
      );
      decipherAuth.setAuthTag(tagAuth);
      let decryptedBufferAuth = Buffer.concat([
        decipherAuth.update(encryptedAuth),
        decipherAuth.final()
      ]);
      if (hasTimestampAuth) {
        const decryptedBase64Auth = decryptedBufferAuth.toString("utf8");
        const fullBufferAuth = Buffer.from(decryptedBase64Auth, "base64");
        const timestampAuth = Number(fullBufferAuth.readBigUInt64BE(0));
        metadata.timestamp = timestampAuth;
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
function deriveAESKeyForDecryption(recipientPrivateKeyStr, ephemeralPublicKeyStr, salt) {
  const recipientPrivateKey = (0, import_crypto17.createPrivateKey)({
    key: Buffer.from(recipientPrivateKeyStr, "base64"),
    format: "der",
    type: "pkcs8"
  });
  const ephemeralPublicKey = (0, import_crypto17.createPublicKey)({
    key: Buffer.from(ephemeralPublicKeyStr, "base64"),
    format: "der",
    type: "spki"
  });
  const sharedSecret = (0, import_crypto17.diffieHellman)({
    privateKey: recipientPrivateKey,
    publicKey: ephemeralPublicKey
  });
  const aesKey = Buffer.from(
    (0, import_crypto17.hkdfSync)("sha256", sharedSecret, salt, "secure-channel-aes-key", 32)
  );
  return aesKey;
}

// src/index.ts
var LIBRARY_VERSION = VERSION;
var MINIMUM_PASSWORD_LENGTH = MIN_PASSWORD_LENGTH;
var MAX_MESSAGE_AGE = MESSAGE_MAX_AGE_MS;
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  LIBRARY_VERSION,
  MAX_MESSAGE_AGE,
  MESSAGE_MAX_AGE_MS,
  MINIMUM_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  VERSION,
  decrypt,
  decryptFile,
  decryptMessage,
  deriveAESKeyForDecryption,
  deriveAESKeyForEncryption,
  encrypt,
  encryptFileStreaming,
  encryptMessage,
  hash,
  keys,
  otp,
  password,
  signature,
  uuid,
  validatePassword,
  validatePrivateKey,
  validatePublicKey,
  validateTimestamp,
  validateVersion
});
