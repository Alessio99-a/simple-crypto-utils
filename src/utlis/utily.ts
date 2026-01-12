import { generateKeyPairSync } from "crypto";

/**
 * Generate RSA key pair for sealEnvelope/openEnvelope mode
 * @returns Object with publicKey and privateKey as base64 strings
 * @example
 * ```ts
 * const { publicKey, privateKey } = generateRSAKeyPair();
 * await encrypt({ type: "sealEnvelope", recipientPublicKey: publicKey }, "Hello");
 * ```
 */
export function generateRSAKeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  };
}

/**
 * Generate X25519 key pair for secure-channel mode
 * @returns Object with publicKey and privateKey as base64 strings
 * @example
 * ```ts
 * const { publicKey, privateKey } = generateX25519KeyPair();
 * await encrypt({ type: "secure-channel", recipientPublicKey: publicKey }, "Hello");
 * ```
 */
export function generateX25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  };
}

/**
 * Generate Ed25519 key pair for authenticated-channel mode (signing)
 * @returns Object with publicKey and privateKey as base64 strings
 * @example
 * ```ts
 * const signingKeys = generateEd25519KeyPair();
 * const encryptionKeys = generateX25519KeyPair();
 *
 * await encrypt({
 *   type: "authenticated-channel",
 *   recipientPublicKey: encryptionKeys.publicKey,
 *   senderPrivateKey: signingKeys.privateKey
 * }, "Authenticated message");
 * ```
 */
export function generateEd25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  };
}

/**
 * Generate complete key set for authenticated channel
 * @returns Object with encryption (X25519) and signing (Ed25519) key pairs
 * @example
 * ```ts
 * const alice = generateAuthenticatedKeySet();
 * const bob = generateAuthenticatedKeySet();
 *
 * // Alice sends to Bob
 * const encrypted = await encrypt({
 *   type: "authenticated-channel",
 *   recipientPublicKey: bob.encryption.publicKey,
 *   senderPrivateKey: alice.signing.privateKey
 * }, "Hello Bob");
 *
 * // Bob decrypts from Alice
 * const decrypted = await decrypt({
 *   type: "authenticated-channel",
 *   recipientPrivateKey: bob.encryption.privateKey,
 *   senderPublicKey: alice.signing.publicKey
 * }, encrypted.data);
 * ```
 */
export function generateAuthenticatedKeySet(): {
  encryption: { publicKey: string; privateKey: string };
  signing: { publicKey: string; privateKey: string };
} {
  return {
    encryption: generateX25519KeyPair(),
    signing: generateEd25519KeyPair(),
  };
}

/**
 * Check if a string is a valid base64-encoded key
 * @param key Base64 string to validate
 * @returns true if valid base64, false otherwise
 */
export function isValidBase64(key: string): boolean {
  try {
    const decoded = Buffer.from(key, "base64");
    const reencoded = decoded.toString("base64");
    return key === reencoded;
  } catch {
    return false;
  }
}

/**
 * Get information about a key (type, length, format)
 * @param keyStr Base64-encoded key
 * @returns Object with key information
 */
export function getKeyInfo(keyStr: string): {
  type: string;
  length: number;
  isPublic: boolean;
} {
  const buffer = Buffer.from(keyStr, "base64");

  // Heuristic detection based on common DER structures
  const isPublic = buffer[0] === 0x30 && buffer[1] === 0x2a; // Common SPKI prefix
  const isPrivate = buffer[0] === 0x30 && buffer[1] === 0x2e; // Common PKCS8 prefix

  let type = "unknown";

  // RSA keys are typically 550+ bytes (4096-bit)
  if (buffer.length > 500) {
    type = "rsa";
  }
  // X25519/Ed25519 keys are 44-48 bytes
  else if (buffer.length >= 40 && buffer.length <= 50) {
    type = "x25519 or ed25519";
  }

  return {
    type,
    length: buffer.length,
    isPublic: isPublic || !isPrivate,
  };
}
