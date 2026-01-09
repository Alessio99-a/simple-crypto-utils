import { sign as signFunction } from "./sign";
import { verify as verifyFunction } from "./verify";
import type { SignOptions, VerifyOptions } from "./types";

export class Signer {
  private defaultOptions: Required<SignOptions>;

  constructor(defaultOptions?: Partial<SignOptions>) {
    this.defaultOptions = {
      strategy: defaultOptions?.strategy ?? "canonical",
      fields: defaultOptions?.fields ?? [],
      algorithm: defaultOptions?.algorithm ?? "SHA256",
      encoding: defaultOptions?.encoding ?? "base64",
      preHash: defaultOptions?.preHash ?? false,
    };
  }

  /**
   * Sign data with private key
   */
  sign(data: any, privateKey: string, options?: SignOptions): string {
    const opts = { ...this.defaultOptions, ...options };
    return signFunction(data, privateKey, opts);
  }

  /**
   * Verify signature with public key
   */
  verify(
    data: any,
    signature: string,
    publicKey: string,
    options?: VerifyOptions
  ): boolean {
    const opts = { ...this.defaultOptions, ...options };
    return verifyFunction(data, signature, publicKey, opts);
  }

  /**
   * Create a signed envelope (data + signature)
   */
  envelope(
    data: any,
    privateKey: string,
    options?: SignOptions
  ): { data: any; signature: string } {
    return {
      data,
      signature: this.sign(data, privateKey, options),
    };
  }

  /**
   * Verify and extract data from signed envelope
   */
  openEnvelope(
    envelope: { data: any; signature: string },
    publicKey: string,
    options?: VerifyOptions
  ): { valid: boolean; data: any } {
    const valid = this.verify(
      envelope.data,
      envelope.signature,
      publicKey,
      options
    );
    return { valid, data: envelope.data };
  }
}

// Export class
export { Signer as default };

export { sign } from "./sign";
export { verify } from "./verify";

export type {
  SignOptions,
  VerifyOptions,
  SerializationStrategy,
} from "./types";

const defaultSigner = new Signer();
export const envelope = defaultSigner.envelope.bind(defaultSigner);
export const openEnvelope = defaultSigner.openEnvelope.bind(defaultSigner);
