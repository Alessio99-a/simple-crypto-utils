import { sign as signFunction } from "./sign";
import { verify as verifyFunction } from "./verify";
import type { SignOptions, VerifyOptions } from "./types";

/**
 * Class for signing and verifying data with digital signatures.
 *
 * Supports:
 * - Signing data
 * - Verifying signatures
 * - Creating signed envelopes (data + signature)
 * - Opening envelopes and verifying validity
 */
export class Signer {
  private defaultOptions: Required<SignOptions>;

  /**
   * Creates a new Signer instance with optional default options.
   *
   * @param defaultOptions - Partial default options to override
   *  serialization strategy, fields, algorithm, encoding, or preHash.
   */
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
  static sign(data: any, privateKey: string, options?: SignOptions): string {
    const opts = {
      strategy: options?.strategy ?? "canonical",
      fields: options?.fields ?? [],
      encoding: options?.encoding ?? "base64",
    } as const;

    const signOpts: {
      strategy?: "canonical";
      fields?: string[];
      encoding?: "base64" | "hex";
    } = {
      fields: opts.fields,
      encoding: opts.encoding,
    };

    if (opts.strategy === "canonical") {
      signOpts.strategy = "canonical";
    }

    return signFunction(data, privateKey, signOpts);
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
  static verify(
    data: any,
    signature: string,
    publicKey: string,
    options?: VerifyOptions
  ): boolean {
    const opts = {
      strategy: options?.strategy ?? "canonical",
      fields: options?.fields ?? [],
      encoding: options?.encoding ?? "base64",
    } as const;

    const verifyOpts: {
      strategy?: "canonical";
      fields?: string[];
      encoding?: "base64" | "hex";
    } = {
      fields: opts.fields,
      encoding: opts.encoding,
    };

    if (opts.strategy === "canonical") {
      verifyOpts.strategy = "canonical";
    }

    return verifyFunction(data, signature, publicKey, verifyOpts);
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
  static envelope(
    data: any,
    privateKey: string,
    options?: SignOptions
  ): { data: any; signature: string } {
    return {
      data,
      signature: Signer.sign(data, privateKey, options),
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
  static openEnvelope(
    envelope: { data: any; signature: string },
    publicKey: string,
    options?: VerifyOptions
  ): { valid: boolean; data: any } {
    const valid = Signer.verify(
      envelope.data,
      envelope.signature,
      publicKey,
      options
    );
    return { valid, data: envelope.data };
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
  sign(data: any, privateKey: string, options?: SignOptions): string {
    const opts = { ...this.defaultOptions, ...options };

    const signOpts: {
      strategy?: "canonical";
      fields?: string[];
      encoding?: "base64" | "hex";
    } = {
      fields: opts.fields,
      encoding: opts.encoding,
    };

    if (opts.strategy === "canonical") {
      signOpts.strategy = "canonical";
    }

    return signFunction(data, privateKey, signOpts);
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
  verify(
    data: any,
    signature: string,
    publicKey: string,
    options?: VerifyOptions
  ): boolean {
    const opts = { ...this.defaultOptions, ...options };

    const verifyOpts: {
      strategy?: "canonical";
      fields?: string[];
      encoding?: "base64" | "hex";
    } = {
      fields: opts.fields,
      encoding: opts.encoding,
    };

    if (opts.strategy === "canonical") {
      verifyOpts.strategy = "canonical";
    }

    return verifyFunction(data, signature, publicKey, verifyOpts);
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

/** Default Signer instance for convenience */
const defaultSigner = new Signer();

/** Convenience functions using the default signer */
export const envelope = defaultSigner.envelope.bind(defaultSigner);
export const openEnvelope = defaultSigner.openEnvelope.bind(defaultSigner);
