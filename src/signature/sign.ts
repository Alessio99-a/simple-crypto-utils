import { createPrivateKey, KeyObject, sign as nodeSign } from "crypto";
import { serialize } from "./serialize";

/**
 * Signs data using a private key and SHA-256.
 *
 * The data is first serialized (optionally using a canonical strategy
 * or selecting specific fields) and then signed using the provided
 * private key. The output can be encoded in Base64 or hex.
 *
 * @param data - The data to sign (any type that can be serialized).
 * @param privateKey - The private key used for signing (PEM or Base64 DER).
 * @param options - Optional signing options:
 *   - `strategy`: Serialization strategy (default: "canonical")
 *   - `fields`: Array of field names to include in serialization (default: all)
 *   - `encoding`: Output encoding, either `"base64"` (default) or `"hex"`
 * @returns The digital signature as a string in the specified encoding.
 *
 * @example
 * ```ts
 * import { sign } from "./sign";
 *
 * const privateKey = "..."; // PEM or Base64 DER
 * const data = { message: "Hello, world!" };
 *
 * const signature = sign(data, privateKey);
 * console.log(signature); // Base64-encoded signature
 *
 * const hexSignature = sign(data, privateKey, { encoding: "hex" });
 * console.log(hexSignature);
 * ```
 */

function parsePrivateKey(key: string): KeyObject {
  const keyObject = createPrivateKey({
    key: Buffer.from(key, "base64"),
    format: "der",
    type: "pkcs8",
  });

  if (keyObject.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected ed25519 key, got ${keyObject.asymmetricKeyType}`);
  }
  return keyObject;
}

export function sign(
  data: any,
  privateKey: string,
  options?: {
    strategy?: "canonical";
    fields?: string[];
    encoding?: "base64" | "hex";
  }
): string {
  const keyObject = parsePrivateKey(privateKey);

  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );

  return nodeSign(
    null, // ✅ Ed25519 requires null
    Buffer.from(serialized),
    keyObject
  ).toString(options?.encoding ?? "base64");
}
