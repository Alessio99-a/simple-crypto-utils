import { sign as nodeSign } from "crypto";
import { serialize } from "./serialize";

export function sign(
  data: any,
  privateKey: string,
  options?: {
    strategy?: "canonical";
    fields?: string[];
    encoding?: "base64" | "hex";
  }
): string {
  const serialized = serialize(
    data,
    options?.strategy ?? "canonical",
    options?.fields ?? []
  );

  return nodeSign("sha256", Buffer.from(serialized), privateKey).toString(
    options?.encoding ?? "base64"
  );
}
