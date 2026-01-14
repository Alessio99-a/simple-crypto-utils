import { KeyObject } from 'crypto';

interface PasswordOptions {
    length?: number;
    letters?: boolean;
    numbers?: boolean;
    symbols?: boolean;
}
declare function generatePassword(length?: number): string;
declare function generatePassword(options: PasswordOptions): string;
declare function generatePassword(options: PasswordOptions & {
    hash: true;
}): Promise<string>;

declare function hashPassword(password: string): Promise<string>;

declare function verifyPassword(password: string, storedHash: string): Promise<boolean>;

declare const index$5_generatePassword: typeof generatePassword;
declare const index$5_hashPassword: typeof hashPassword;
declare const index$5_verifyPassword: typeof verifyPassword;
declare namespace index$5 {
  export { index$5_generatePassword as generatePassword, index$5_hashPassword as hashPassword, index$5_verifyPassword as verifyPassword };
}

declare function generateUUID(): string;

declare const index$4_generateUUID: typeof generateUUID;
declare namespace index$4 {
  export { index$4_generateUUID as generateUUID };
}

type SerializationStrategy = "canonical" | "raw" | "selective";
interface SignOptions {
    strategy?: SerializationStrategy;
    fields?: string[];
    algorithm?: "SHA256" | "SHA384" | "SHA512";
    encoding?: "base64" | "hex";
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

declare class Signer {
    private defaultOptions;
    constructor(defaultOptions?: Partial<SignOptions>);
    static sign(data: any, privateKey: string, options?: SignOptions): string;
    static verify(data: any, signature: string, publicKey: string, options?: VerifyOptions): boolean;
    static envelope(data: any, privateKey: string, options?: SignOptions): {
        data: any;
        signature: string;
    };
    static openEnvelope(envelope: {
        data: any;
        signature: string;
    }, publicKey: string, options?: VerifyOptions): {
        valid: boolean;
        data: any;
    };
    sign(data: any, privateKey: string, options?: SignOptions): string;
    verify(data: any, signature: string, publicKey: string, options?: VerifyOptions): boolean;
    envelope(data: any, privateKey: string, options?: SignOptions): {
        data: any;
        signature: string;
    };
    openEnvelope(envelope: {
        data: any;
        signature: string;
    }, publicKey: string, options?: VerifyOptions): {
        valid: boolean;
        data: any;
    };
}

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

declare function hash(data: string): string;

declare function hashHmac(secret: string, data: string): string;

declare function verifyHmac(secret: string, data: string, expectedHex: string): boolean;

declare const index$2_hash: typeof hash;
declare const index$2_hashHmac: typeof hashHmac;
declare const index$2_verifyHmac: typeof verifyHmac;
declare namespace index$2 {
  export { index$2_hash as hash, index$2_hashHmac as hashHmac, index$2_verifyHmac as verifyHmac };
}

declare function generateECDHKeyPair(): {
    publicKey: string;
    privateKey: string;
};

declare function generateRSAKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
}>;

type keyType = "seal" | "sign" | "secure-channel" | "authenticated-channel";
declare class Key {
    publicKey?: string;
    privateKey?: string;
    signingPublicKey?: string;
    signingPrivateKey?: string;
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

declare function generateTOTP(secret: string, digits?: number, period?: number, timestamp?: number): string;

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
declare function validatePassword(password: string, strictMode?: boolean): void;
declare function validatePublicKey(keyStr: string, expectedType: "rsa" | "x25519"): void;
declare function validatePrivateKey(keyStr: string, expectedType: "rsa" | "ed25519"): void;
declare function encrypt(options: SymmetricPasswordOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
declare function encrypt(options: SealEnvelopeOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
declare function encrypt(options: SecureChannelOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
declare function encrypt(options: AuthenticatedChannelOptions$1, data: MessageData$1): Promise<EncryptResult$1>;
declare function encrypt(options: SymmetricPasswordOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
declare function encrypt(options: SealEnvelopeOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
declare function encrypt(options: SecureChannelOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
declare function encrypt(options: AuthenticatedChannelOptions$1, data: null | undefined, inputPath: string, outputPath: string): Promise<EncryptResult$1>;
declare function encryptFileStreaming(options: MessageEncryptOptions, inputPath: string, outputPath: string): Promise<void>;
declare function encryptMessage(options: MessageEncryptOptions, data: MessageData$1): string;
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
declare function validateTimestamp(timestamp: number, maxAge?: number): void;
declare function validateVersion(version: number): void;
declare function decrypt(options: SymmetricPasswordDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
declare function decrypt(options: OpenEnvelopeDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
declare function decrypt(options: SecureChannelDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
declare function decrypt(options: AuthenticatedChannelDecryptOptions, data: MessageData): Promise<MessageDecryptResult>;
declare function decrypt(options: SymmetricPasswordDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
declare function decrypt(options: OpenEnvelopeDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
declare function decrypt(options: SecureChannelDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
declare function decrypt(options: AuthenticatedChannelDecryptOptions, data: null | undefined, inputPath: string, outputPath: string): Promise<FileDecryptResult>;
declare function decryptFile(options: MessageDecryptOptions, inputPath: string, outputPath: string): Promise<void>;
declare function decryptMessage(options: MessageDecryptOptions, encryptedHex: string): {
    data: string | object;
    metadata?: DecryptMetadata;
};
declare function deriveAESKeyForDecryption(recipientPrivateKeyStr: string, ephemeralPublicKeyStr: string, salt: Buffer): Buffer;

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
