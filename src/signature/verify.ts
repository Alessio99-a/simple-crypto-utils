import { createPublicKey, KeyObject, verify as nodeVerify } from "crypto";
import { serialize } from "./serialize";

function parsePublicKey(key: string): KeyObject {
  const keyObject = createPublicKey({
    key: Buffer.from(key, "base64"),
    format: "der",
    type: "spki",
  });

  if (keyObject.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected ed25519 key, got ${keyObject.asymmetricKeyType}`);
  }

  return keyObject;
}

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
  const keyObject = parsePublicKey(publicKey);

  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );

  return nodeVerify(
    null, // ✅ required for ed25519
    Buffer.from(serialized),
    keyObject,
    Buffer.from(signature, options?.encoding ?? "base64")
  );
}
