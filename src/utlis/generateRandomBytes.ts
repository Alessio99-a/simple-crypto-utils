import { randomBytes } from "crypto";
import { MAX_BYTES } from "./constants";

export function generateRandomBytes(size: number): Buffer {
  if (size > MAX_BYTES) {
    throw new Error(`Cannot generate more than ${MAX_BYTES} bytes`);
  }
  return randomBytes(size);
}
