import { verify as nodeVerify } from "crypto";
import { serialize } from "./serialize";

export function verify(
  data: any,
  signature: string,
  publicKey: string,
  options?: {
    strategy?: "canonical";
    fields?: string[];
    encoding?: "base64" | "hex";
  }
): boolean {
  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );

  return nodeVerify(
    "sha256",
    Buffer.from(serialized),
    publicKey,
    Buffer.from(signature, options?.encoding ?? "base64")
  );
}
