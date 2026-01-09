import { createVerify, createHash } from "crypto";
import { serialize } from "./serialize";
import type { VerifyOptions } from "./types";

export function verify(
  data: any,
  signature: string,
  publicKey: string,
  options?: VerifyOptions
): boolean {
  const opts = {
    strategy: options?.strategy ?? "canonical",
    fields: options?.fields ?? [],
    algorithm: options?.algorithm ?? "SHA256",
    encoding: options?.encoding ?? "base64",
    preHash: options?.preHash ?? false,
  } as const;

  const serialized = serialize(data, opts.strategy, opts.fields);

  let dataToVerify: Buffer | string;

  if (opts.preHash) {
    dataToVerify = createHash(opts.algorithm.toLowerCase())
      .update(serialized)
      .digest();
  } else {
    dataToVerify = serialized;
  }

  const verifier = createVerify(opts.algorithm);
  verifier.update(dataToVerify);
  verifier.end();

  return verifier.verify(publicKey, signature, opts.encoding);
}
