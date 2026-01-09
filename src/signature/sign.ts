import { createSign, createHash } from "crypto";
import { serialize } from "./serialize";
import type { SignOptions } from "./types";

export function sign(
  data: any,
  privateKey: string,
  options?: SignOptions
): string {
  const opts = {
    strategy: options?.strategy ?? "canonical",
    fields: options?.fields ?? [],
    algorithm: options?.algorithm ?? "SHA256",
    encoding: options?.encoding ?? "base64",
    preHash: options?.preHash ?? false,
  } as const;

  const serialized = serialize(data, opts.strategy, opts.fields);

  let dataToSign: Buffer | string;

  if (opts.preHash) {
    dataToSign = createHash(opts.algorithm.toLowerCase())
      .update(serialized)
      .digest();
  } else {
    dataToSign = serialized;
  }

  const signer = createSign(opts.algorithm);
  signer.update(dataToSign);
  signer.end();

  return signer.sign(privateKey, opts.encoding);
}
