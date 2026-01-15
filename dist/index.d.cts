import { KeyObject } from 'crypto';

interface PasswordOptions {
    /** Length of the password (default: 16) */
    length?: number;
    /** Include letters in the password (default: true) */
    letters?: boolean;
    /** Include numbers in the password (default: true) */
    numbers?: boolean;
    /** Include symbols in the password (default: true) */
    symbols?: boolean;
}
declare function generatePassword(length?: number): string;
declare function generatePassword(options: PasswordOptions): string;
declare function generatePassword(options: PasswordOptions & {
    hash: true;
}): Promise<string>;

/**
 * Generates a secure scrypt hash of a password.
 *
 * The hash is salted with 16 random bytes and the result is encoded in Base64.
 * The output format is:
 * ```
 * scrypt$16$<saltBase64>$<hashBase64>
 * ```
 *
 * @param password - The password to hash.
 * @returns A Promise resolving to the hashed password string.
 *
 * @example
 * ```ts
 * import { hashPassword } from "./password";
 *
 * async function main() {
 *   const hashed = await hashPassword("mySecretPassword");
 *   console.log(hashed);
 *   // Example output:
 *   // scrypt$16$3q2+7w==$pX9n0V5gK2v7r6Y3h8Zs2I3cL0y7hGqL8v9pN7l0K5Q=
 * }
 *
 * main();
 * ```
 */
declare function hashPassword(password: string): Promise<string>;

/**
 * Validates a password against a stored scrypt hash.
 *
 * The stored hash must be in the format:
 * ```
 * scrypt$<saltLength>$<saltBase64>$<hashBase64>
 * ```
 * The function uses a constant-time comparison to prevent timing attacks.
 *
 * @param password - The password to verify.
 * @param storedHash - The stored hash string to validate against.
 * @returns `true` if the password matches the hash, `false` otherwise.
 *
 * @example
 * ```ts
 * import { hash } from "./password";
 * import { verifyPassword } from "./validate";
 *
 * async function main() {
 *   const password = "mySecretPassword";
 *   const hashed = await hash(password);
 *
 *   const isValid = await verifyPassword("mySecretPassword", hashed);
 *   console.log(isValid); // true
 *
 *   const isInvalid = await verifyPassword("wrongPassword", hashed);
 *   console.log(isInvalid); // false
 * }
 *
 * main();
 * ```
 */
declare function verifyPassword(password: string, storedHash: string): Promise<boolean>;

declare const index$5_generatePassword: typeof generatePassword;
declare const index$5_hashPassword: typeof hashPassword;
declare const index$5_verifyPassword: typeof verifyPassword;
declare namespace index$5 {
  export { index$5_generatePassword as generatePassword, index$5_hashPassword as hashPassword, index$5_verifyPassword as verifyPassword };
}

/**
 * Generates a cryptographically secure UUID (version 4).
 *
 * @returns A string representing the UUID (e.g., "3b241101-e2bb-4255-8caf-4136c566a962").
 *
 * @example
 * ```ts
 * import { generateUUID } from "./uuid";
 *
 * const id = generateUUID();
 * console.log(id); // e.g., "3b241101-e2bb-4255-8caf-4136c566a962"
 * ```
 */
declare function generateUUID(): string;

declare const index$4_generateUUID: typeof generateUUID;
declare namespace index$4 {
  export { index$4_generateUUID as generateUUID };
}

type SerializationStrategy = "canonical" | "raw" | "selective";
interface SignOptions {
    /** Serialization strategy for complex objects */
    strategy?: SerializationStrategy;
    /** Fields to sign when using 'selective' strategy */
    fields?: string[];
    /** Hash algorithm (default: 'SHA256') */
    algorithm?: "SHA256" | "SHA384" | "SHA512";
    /** Output encoding (default: 'base64') */
    encoding?: "base64" | "hex";
    /** Pre-hash large data before signing (recommended for >1MB) */
    preHash?: boolean;
}
interface VerifyOptions extends SignOptions {
}

declare function sign(data: any, privateKey: string, options?: {
    strategy?: "canonical";
    fields?: string[];
    encoding?: "base64" | "hex";
}): string;

declare function verify(data: any, signature: string, publicKey: string, options?: {
    strategy?: "canonical";
    fields?: string[];
    encoding?: "base64" | "hex";
}): boolean;

/**
 * Class for signing and verifying data with digital signatures.
 *
 * Supports:
 * - Signing data
 * - Verifying signatures
 * - Creating signed envelopes (data + signature)
 * - Opening envelopes and verifying validity
 */
declare class Signer {
    private defaultOptions;
    /**
     * Creates a new Signer instance with optional default options.
     *
     * @param defaultOptions - Partial default options to override
     *  serialization strategy, fields, algorithm, encoding, or preHash.
     */
    constructor(defaultOptions?: Partial<SignOptions>);
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
    static sign(data: any, privateKey: string, options?: SignOptions): string;
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
    static verify(data: any, signature: string, publicKey: string, options?: VerifyOptions): boolean;
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
    static envelope(data: any, privateKey: string, options?: SignOptions): {
        data: any;
        signature: string;
    };
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
    static openEnvelope(envelope: {
        data: any;
        signature: string;
    }, publicKey: string, options?: VerifyOptions): {
        valid: boolean;
        data: any;
    };
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
    sign(data: any, privateKey: string, options?: SignOptions): string;
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
    verify(data: any, signature: string, publicKey: string, options?: VerifyOptions): boolean;
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
    envelope(data: any, privateKey: string, options?: SignOptions): {
        data: any;
        signature: string;
    };
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
    openEnvelope(envelope: {
        data: any;
        signature: string;
    }, publicKey: string, options?: VerifyOptions): {
        valid: boolean;
        data: any;
    };
}

/** Convenience functions using the default signer */
declare const envelope: (data: any, privateKey: string, options?: SignOptions) => {
    data: any;
    signature: string;
};
declare const openEnvelope: (envelope: {
    data: any;
    signature: string;
}, publicKey: string, options?: VerifyOptions) => {
    valid: boolean;
    data: any;
};

type index$3_SerializationStrategy = SerializationStrategy;
type index$3_SignOptions = SignOptions;
type index$3_Signer = Signer;
declare const index$3_Signer: typeof Signer;
type index$3_VerifyOptions = VerifyOptions;
declare const index$3_envelope: typeof envelope;
declare const index$3_openEnvelope: typeof openEnvelope;
declare const index$3_sign: typeof sign;
declare const index$3_verify: typeof verify;
declare namespace index$3 {
  export { type index$3_SerializationStrategy as SerializationStrategy, type index$3_SignOptions as SignOptions, index$3_Signer as Signer, type index$3_VerifyOptions as VerifyOptions, Signer as default, index$3_envelope as envelope, index$3_openEnvelope as openEnvelope, index$3_sign as sign, index$3_verify as verify };
}

/**
 * Computes the SHA-256 hash of a given string.
 *
 * @param data - The input string to hash.
 * @returns The SHA-256 hash of the input as a hexadecimal string.
 *
 * @example
 * ```ts
 * import { hash } from "./hash";
 *
 * const data = "Hello, world!";
 * const hashed = hash(data);
 *
 * console.log(hashed); // e.g., "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b247724e5b3f6d0f8c13f0"
 * ```
 */
declare function hash(data: string): string;

/**
 * Computes a SHA-256 HMAC for a given string using a secret key.
 *
 * HMAC (Hash-based Message Authentication Code) ensures both
 * data integrity and authenticity.
 *
 * @param secret - The secret key used to compute the HMAC.
 * @param data - The input string to hash.
 * @returns The HMAC as a hexadecimal string.
 *
 * @example
 * ```ts
 * import { hashHmac } from "./hmac";
 *
 * const secret = "mysecretkey";
 * const message = "Hello, world!";
 * const hmac = hashHmac(secret, message);
 *
 * console.log(hmac); // e.g., "a6f5c3b2e4d1..."
 * ```
 */
declare function hashHmac(secret: string, data: string): string;

/**
 * Verifies a SHA-256 HMAC for a given string using a secret key.
 *
 * This function uses a **timing-safe comparison** to prevent
 * timing attacks when comparing the expected HMAC to the actual one.
 *
 * @param secret - The secret key used to compute the HMAC.
 * @param data - The input string to hash.
 * @param expectedHex - The expected HMAC in hexadecimal format.
 * @returns `true` if the computed HMAC matches the expected one, `false` otherwise.
 *
 * @example
 * ```ts
 * import { hashHmac, verifyHmac } from "./hmac";
 *
 * const secret = "mysecretkey";
 * const message = "Hello, world!";
 *
 * const hmac = hashHmac(secret, message);
 * const isValid = verifyHmac(secret, message, hmac);
 *
 * console.log(isValid); // true
 * ```
 */
declare function verifyHmac(secret: string, data: string, expectedHex: string): boolean;

declare const index$2_hash: typeof hash;
declare const index$2_hashHmac: typeof hashHmac;
declare const index$2_verifyHmac: typeof verifyHmac;
declare namespace index$2 {
  export { index$2_hash as hash, index$2_hashHmac as hashHmac, index$2_verifyHmac as verifyHmac };
}

/**
 * Generates an X25519 key pair for Elliptic Curve Diffie-Hellman (ECDH).
 *
 * The keys are exported in DER format and encoded as Base64 strings:
 * - Public key: SPKI (SubjectPublicKeyInfo)
 * - Private key: PKCS#8
 *
 * This key pair is suitable for secure key agreement protocols.
 *
 * @returns An object containing:
 *  - `publicKey`: Base64-encoded X25519 public key (DER, SPKI)
 *  - `privateKey`: Base64-encoded X25519 private key (DER, PKCS#8)
 *
 * @example
 * ```ts
 * import { generateECDHKeyPair } from "./ecdh";
 *
 * const { publicKey, privateKey } = generateECDHKeyPair();
 *
 * console.log(publicKey);  // Send to the peer
 * console.log(privateKey); // Keep secret
 * ```
 */
declare function generateECDHKeyPair(): {
    publicKey: string;
    privateKey: string;
};

/**
 * Generates an RSA key pair for encryption or digital signatures.
 *
 * - Algorithm: RSA
 * - Key size: 2048 bits
 * - Public key: SPKI (DER, base64-encoded)
 * - Private key: PKCS#8 (DER, base64-encoded)
 *
 * @returns A Promise that resolves to an object containing:
 *  - `publicKey`: RSA public key in base64-encoded DER format
 *  - `privateKey`: RSA private key in base64-encoded DER format
 *
 * @example
 * ```ts
 * import { generateRSAKeyPair } from "./rsa";
 *
 * async function main() {
 *   const { publicKey, privateKey } = await generateRSAKeyPair();
 *
 *   console.log(publicKey);  // Can be shared (base64 string)
 *   console.log(privateKey); // Keep secret (base64 string)
 * }
 *
 * main();
 * ```
 */
declare function generateRSAKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
}>;

type keyType = "seal" | "sign" | "secure-channel" | "authenticated-channel";
/**
 * Represents a cryptographic key or key pair for various use cases.
 *
 * Depending on the `keyType`, the instance may contain:
 * - Encryption keys (`publicKey` / `privateKey`)
 * - Signing keys (`signingPublicKey` / `signingPrivateKey`)
 */
declare class Key {
    /** Public key for encryption or signing (Base64 or PEM depending on type) */
    publicKey?: string;
    /** Private key for encryption or signing (Base64 or PEM depending on type) */
    privateKey?: string;
    /** Public key specifically for signing (Base64) */
    signingPublicKey?: string;
    /** Private key specifically for signing (Base64) */
    signingPrivateKey?: string;
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
    static generate(key: keyType): Promise<Key>;
}

type index$1_Key = Key;
declare const index$1_Key: typeof Key;
declare const index$1_generateECDHKeyPair: typeof generateECDHKeyPair;
declare const index$1_generateRSAKeyPair: typeof generateRSAKeyPair;
type index$1_keyType = keyType;
declare namespace index$1 {
  export { index$1_Key as Key, index$1_generateECDHKeyPair as generateECDHKeyPair, index$1_generateRSAKeyPair as generateRSAKeyPair, type index$1_keyType as keyType };
}

/**
 * Generates a Time-based One-Time Password (TOTP) according to RFC 6238.
 *
 * @param secret - The shared secret in Base32 encoding.
 * @param digits - Number of digits in the OTP (default: 6).
 * @param period - Time step in seconds (default: 30).
 * @param timestamp - Unix timestamp in milliseconds (default: current time).
 * @returns A numeric OTP as a string, zero-padded to the specified length.
 *
 * @example
 * ```ts
 * import { generateTOTP } from "./totp";
 *
 * const secret = "JBSWY3DPEHPK3PXP"; // Base32 secret
 * const otp = generateTOTP(secret);
 * console.log(otp); // e.g., "492039"
 *
 * // Generate a 8-digit OTP with a 60-second period
 * const otp8 = generateTOTP(secret, 8, 60);
 * console.log(otp8);
 * ```
 */
declare function generateTOTP(secret: string, digits?: number, period?: number, timestamp?: number): string;

/**
 * Generates a numeric one-time password (OTP) of a specified length.
 *
 * The OTP consists only of digits (0–9) and is padded with leading zeros
 * if necessary.
 *
 * @param length - The length of the OTP (default: 6). Must be a positive integer.
 * @returns A string representing the numeric OTP.
 *
 * @example
 * ```ts
 * import { generateOTP } from "./otp";
 *
 * const otp = generateOTP();       // e.g., "084321"
 * const otp8 = generateOTP(8);     // e.g., "09238475"
 *
 * console.log(otp, otp8);
 * ```
 */
declare function generateOTP(length?: number): string;

declare const index_generateOTP: typeof generateOTP;
declare const index_generateTOTP: typeof generateTOTP;
declare namespace index {
  export { index_generateOTP as generateOTP, index_generateTOTP as generateTOTP };
}

declare const VERSION = 1;
declare const MIN_PASSWORD_LENGTH = 12;
declare const MESSAGE_MAX_AGE_MS: number;
interface EncryptResult$1 {
    type: "file" | "message";
    data?: string;
    outputPath?: string;
}
interface SymmetricPasswordOptions$1 {
    type: "symmetric-password";
    password: string;
    strictMode?: boolean;
}
interface SealEnvelopeOptions$1 {
    type: "sealEnvelope";
    recipientPublicKey: string;
    strictMode?: boolean;
}
interface SecureChannelOptions$1 {
    type: "secure-channel";
    recipientPublicKey: string;
    includeTimestamp?: boolean;
    strictMode?: boolean;
}
interface AuthenticatedChannelOptions$1 {
    type: "authenticated-channel";
    recipientPublicKey: string;
    senderPrivateKey: string;
    includeTimestamp?: boolean;
    strictMode?: boolean;
}
type MessageEncryptOptions = SymmetricPasswordOptions$1 | SealEnvelopeOptions$1 | SecureChannelOptions$1 | AuthenticatedChannelOptions$1;
type MessageData$1 = string | object | Buffer;
/**
 * Validates password strength
 * @param password - The password to validate
 * @param strictMode - If true, enforces stricter validation rules
 * @throws {Error} If password is too short or doesn't meet requirements
 * @example
 * validatePassword("MyP@ssw0rd123", false);
 */
declare function validatePassword(password: string, strictMode?: boolean): void;
/**
 * Validates public key format and type
 * @param keyStr - Base64-encoded public key in SPKI format
 * @param expectedType - Expected key type ('rsa' or 'x25519')
 * @throws {Error} If key is invalid or doesn't match expected type
 * @example
 * validatePublicKey("MIIBIjANBgkq...", "rsa");
 */
declare function validatePublicKey(keyStr: string, expectedType: "rsa" | "x25519"): void;
/**
 * Validates private key format and type
 * @param keyStr - Base64-encoded private key in PKCS8 format
 * @param expectedType - Expected key type ('rsa' or 'ed25519')
 * @throws {Error} If key is invalid or doesn't match expected type
 * @example
 * validatePrivateKey("MIIEvQIBADANBgkq...", "ed25519");
 */
declare function validatePrivateKey(keyStr: string, expectedType: "rsa" | "ed25519"): void;
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
declare function encrypt(options: SymmetricPasswordOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
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
declare function encrypt(options: SealEnvelopeOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
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
declare function encrypt(options: SecureChannelOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
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
declare function encrypt(options: AuthenticatedChannelOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
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
declare function encrypt(options: SymmetricPasswordOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
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
declare function encrypt(options: SealEnvelopeOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
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
declare function encrypt(options: SecureChannelOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
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
declare function encrypt(options: AuthenticatedChannelOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
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
declare function encryptFileStreaming(options: MessageEncryptOptions, inputPath: string, outputPath: string): Promise<void>;
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
declare function encryptMessage(options: MessageEncryptOptions, data: MessageData$1): string;
/**
 * Generate ephemeral key pair and derive AES key using ECDH
 * @param recipientPublicKeyStr - Base64-encoded X25519 public key
 * @returns Object containing derived AES key and ephemeral keys
 * @example
 * const derived = deriveAESKeyForEncryption("MCowBQYDK2VuAyEA...");
 * console.log(derived.aesKey.length); // 32 bytes
 */
declare function deriveAESKeyForEncryption(recipientPublicKeyStr: string): {
    aesKey: Buffer;
    ephemeralPublicKey: string;
    ephemeralPrivateKey: KeyObject;
    salt: Buffer;
};

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
type MessageDecryptOptions = SymmetricPasswordDecryptOptions | OpenEnvelopeDecryptOptions | SecureChannelDecryptOptions | AuthenticatedChannelDecryptOptions;
type MessageData = string | Buffer;
/**
 * Validate timestamp to prevent replay attacks
 * @param timestamp - Unix timestamp in milliseconds
 * @param maxAge - Maximum allowed age in milliseconds
 * @throws {Error} If timestamp is invalid or too old
 * @example
 * validateTimestamp(Date.now() - 60000); // Valid: 1 minute old
 * validateTimestamp(Date.now() - 600000); // Invalid: 10 minutes old (exceeds 5 min default)
 */
declare function validateTimestamp(timestamp: number, maxAge?: number): void;
/**
 * Validate format version
 * @param version - Version number from encrypted data
 * @throws {Error} If version is not supported
 * @example
 * validateVersion(0x01); // Valid
 * validateVersion(0x99); // Throws error
 */
declare function validateVersion(version: number): void;
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
declare function decrypt(options: SymmetricPasswordDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
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
declare function decrypt(options: OpenEnvelopeDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
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
declare function decrypt(options: SecureChannelDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
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
declare function decrypt(options: AuthenticatedChannelDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
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
declare function decrypt(options: SymmetricPasswordDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
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
declare function decrypt(options: OpenEnvelopeDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
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
declare function decrypt(options: SecureChannelDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
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
declare function decrypt(options: AuthenticatedChannelDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
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
declare function decryptFile(options: MessageDecryptOptions, inputPath: string, outputPath: string): Promise<void>;
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
declare function decryptMessage(options: MessageDecryptOptions, encryptedHex: string): {
    data: string | object;
    metadata?: DecryptMetadata;
};
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
declare function deriveAESKeyForDecryption(recipientPrivateKeyStr: string, ephemeralPublicKeyStr: string, salt: Buffer): Buffer;

/**
 * Crypto Utils - Main Export File
 *
 * A comprehensive educational cryptography library implementing:
 * - Symmetric encryption (AES-256-GCM with password)
 * - Asymmetric encryption (RSA-OAEP)
 * - ECDH key exchange (X25519)
 * - Digital signatures (Ed25519)
 * - Forward secrecy
 * - Replay attack prevention
 * -
 * @module crypto-utils
 * @version 1.0.0
 */

interface SymmetricPasswordOptions {
    type: "symmetric-password";
    password: string;
    stream?: boolean;
    strictMode?: boolean;
}
interface SealEnvelopeOptions {
    type: "sealEnvelope";
    recipientPublicKey: string;
    stream?: boolean;
    strictMode?: boolean;
}
interface SecureChannelOptions {
    type: "secure-channel";
    recipientPublicKey: string;
    includeTimestamp?: boolean;
    stream?: boolean;
    strictMode?: boolean;
}
interface AuthenticatedChannelOptions {
    type: "authenticated-channel";
    recipientPublicKey: string;
    senderPrivateKey: string;
    includeTimestamp?: boolean;
    stream?: boolean;
    strictMode?: boolean;
}
type EncryptOptions = SymmetricPasswordOptions | SealEnvelopeOptions | SecureChannelOptions | AuthenticatedChannelOptions;
interface DecryptSymmetricOptions {
    type: "symmetric-password";
    password: string;
    strictMode?: boolean;
}
interface DecryptEnvelopeOptions {
    type: "openEnvelope";
    recipientPrivateKey: string;
    strictMode?: boolean;
}
interface DecryptSecureChannelOptions {
    type: "secure-channel";
    recipientPrivateKey: string;
    validateTimestamp?: boolean;
    strictMode?: boolean;
}
interface DecryptAuthenticatedOptions {
    type: "authenticated-channel";
    recipientPrivateKey: string;
    senderPublicKey: string;
    validateTimestamp?: boolean;
    strictMode?: boolean;
}
type DecryptOptions = DecryptSymmetricOptions | DecryptEnvelopeOptions | DecryptSecureChannelOptions | DecryptAuthenticatedOptions;
interface EncryptResult {
    type: "file" | "message";
    data?: string;
    outputPath?: string;
}
interface DecryptResult {
    type: "file" | "message";
    data?: string | object;
    outputPath?: string;
    metadata?: {
        timestamp?: number;
        authenticated?: boolean;
    };
}
interface KeyPair {
    publicKey: string;
    privateKey: string;
}
interface AuthenticatedKeySet {
    encryption: KeyPair;
    signing: KeyPair;
}
declare const LIBRARY_VERSION = 1;
declare const MINIMUM_PASSWORD_LENGTH = 12;
declare const MAX_MESSAGE_AGE: number;

export { type AuthenticatedChannelOptions, type AuthenticatedKeySet, type DecryptAuthenticatedOptions, type DecryptEnvelopeOptions, type DecryptOptions, type DecryptResult, type DecryptSecureChannelOptions, type DecryptSymmetricOptions, type EncryptOptions, type EncryptResult, type KeyPair, LIBRARY_VERSION, MAX_MESSAGE_AGE, MESSAGE_MAX_AGE_MS, MINIMUM_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, type SealEnvelopeOptions, type SecureChannelOptions, type SymmetricPasswordOptions, VERSION, decrypt, decryptFile, decryptMessage, deriveAESKeyForDecryption, deriveAESKeyForEncryption, encrypt, encryptFileStreaming, encryptMessage, index$2 as hash, index$1 as keys, index as otp, index$5 as password, index$3 as signature, index$4 as uuid, validatePassword, validatePrivateKey, validatePublicKey, validateTimestamp, validateVersion };
