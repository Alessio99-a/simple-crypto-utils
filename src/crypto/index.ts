import { encrypt as e } from "./encrypt";
import { decrypt as d } from "./decrypt";

export class Crypt {
  type: "secure-channel" | "symmetric" | "seal";
  recipientPublicKey?: string;
  recipientPrivateKey?: string;
  password?: string;

  constructor(protocol: "secure-channel" | "symmetric" | "seal") {
    this.type = protocol;
  }

  /**
   * Set the password for symmetric encryption
   */
  setPassword(password: string): this {
    if (this.type !== "symmetric") {
      throw new Error("Password can only be set for symmetric mode");
    }
    this.password = password;
    return this;
  }

  /**
   * Set the recipient's public key (for seal or secure-channel)
   */
  setRecipientPublicKey(key: string): this {
    if (this.type === "symmetric") {
      throw new Error("Public key not used in symmetric mode");
    }
    this.recipientPublicKey = key;
    return this;
  }

  /**
   * Set the recipient's private key (for decryption)
   */
  setRecipientPrivateKey(key: string): this {
    if (this.type === "symmetric") {
      throw new Error("Private key not used in symmetric mode");
    }
    this.recipientPrivateKey = key;
    return this;
  }

  /**
   * Encrypt a message
   */
  async encrypt(message: string | object | Buffer): Promise<string> {
    switch (this.type) {
      case "symmetric":
        if (!this.password) {
          throw new Error("Password not set for symmetric encryption");
        }
        const resultSym = await e(
          { type: "symmetric-password", password: this.password },
          message
        );
        return resultSym.data!;

      case "seal":
        if (!this.recipientPublicKey) {
          throw new Error("Recipient public key not set for seal mode");
        }
        const resultSeal = await e(
          { type: "sealEnvelope", recipientPublicKey: this.recipientPublicKey },
          message
        );
        return resultSeal.data!;

      case "secure-channel":
        if (!this.recipientPublicKey) {
          throw new Error(
            "Recipient public key not set for secure-channel mode"
          );
        }
        const resultChannel = await e(
          {
            type: "secure-channel",
            recipientPublicKey: this.recipientPublicKey,
          },
          message
        );
        return resultChannel.data!;

      default:
        throw new Error(`Unsupported protocol: ${this.type}`);
    }
  }

  /**
   * Decrypt a message
   */
  async decrypt(encryptedHex: string): Promise<string | object> {
    switch (this.type) {
      case "symmetric":
        if (!this.password) {
          throw new Error("Password not set for symmetric decryption");
        }
        const resultSym = await d(
          { type: "symmetric-password", password: this.password },
          encryptedHex
        );
        return resultSym.data!;

      case "seal":
        if (!this.recipientPrivateKey) {
          throw new Error("Recipient private key not set for seal mode");
        }
        const resultSeal = await d(
          {
            type: "openEnvelope",
            recipientPrivateKey: this.recipientPrivateKey,
          },
          encryptedHex
        );
        return resultSeal.data!;

      case "secure-channel":
        if (!this.recipientPrivateKey) {
          throw new Error(
            "Recipient private key not set for secure-channel mode"
          );
        }
        const resultChannel = await d(
          {
            type: "secure-channel",
            recipientPrivateKey: this.recipientPrivateKey,
          },
          encryptedHex
        );
        return resultChannel.data!;

      default:
        throw new Error(`Unsupported protocol: ${this.type}`);
    }
  }

  /**
   * Encrypt a file
   */
  async encryptFile(inputPath: string, outputPath: string): Promise<void> {
    switch (this.type) {
      case "symmetric":
        if (!this.password) {
          throw new Error("Password not set for symmetric encryption");
        }
        await (e as any)(
          { type: "symmetric-password", password: this.password },
          undefined,
          inputPath,
          outputPath
        );
        break;

      case "seal":
        if (!this.recipientPublicKey) {
          throw new Error("Recipient public key not set for seal mode");
        }
        await (e as any)(
          { type: "sealEnvelope", recipientPublicKey: this.recipientPublicKey },
          undefined,
          inputPath,
          outputPath
        );
        break;

      case "secure-channel":
        if (!this.recipientPublicKey) {
          throw new Error(
            "Recipient public key not set for secure-channel mode"
          );
        }
        await (e as any)(
          {
            type: "secure-channel",
            recipientPublicKey: this.recipientPublicKey,
          },
          undefined,
          inputPath,
          outputPath
        );
        break;

      default:
        throw new Error(`Unsupported protocol: ${this.type}`);
    }
  }

  /**
   * Decrypt a file
   */
  async decryptFile(inputPath: string, outputPath: string): Promise<void> {
    switch (this.type) {
      case "symmetric":
        if (!this.password) {
          throw new Error("Password not set for symmetric decryption");
        }
        await (d as any)(
          { type: "symmetric-password", password: this.password },
          "",
          inputPath,
          outputPath
        );
        break;

      case "seal":
        if (!this.recipientPrivateKey) {
          throw new Error("Recipient private key not set for seal mode");
        }
        await (d as any)(
          {
            type: "openEnvelope",
            recipientPrivateKey: this.recipientPrivateKey,
          },
          "",
          inputPath,
          outputPath
        );
        break;

      case "secure-channel":
        if (!this.recipientPrivateKey) {
          throw new Error(
            "Recipient private key not set for secure-channel mode"
          );
        }
        await (d as any)(
          {
            type: "secure-channel",
            recipientPrivateKey: this.recipientPrivateKey,
          },
          "",
          inputPath,
          outputPath
        );
        break;

      default:
        throw new Error(`Unsupported protocol: ${this.type}`);
    }
  }
}

// Example usage:
/*
// Symmetric encryption
const cryptSym = new Crypt("symmetric");
cryptSym.setPassword("mySecretPassword");
const encrypted = await cryptSym.encrypt("Hello World");
const decrypted = await cryptSym.decrypt(encrypted);

// Seal envelope (RSA + AES)
const cryptSeal = new Crypt("seal");
cryptSeal.setRecipientPublicKey(publicKey);
const encrypted2 = await cryptSeal.encrypt("Hello World");

cryptSeal.setRecipientPrivateKey(privateKey);
const decrypted2 = await cryptSeal.decrypt(encrypted2);

// Secure channel (ECDH)
const cryptChannel = new Crypt("secure-channel");
cryptChannel.setRecipientPublicKey(recipientPublicKey);
const encrypted3 = await cryptChannel.encrypt("Hello World");

cryptChannel.setRecipientPrivateKey(recipientPrivateKey);
const decrypted3 = await cryptChannel.decrypt(encrypted3);
*/
