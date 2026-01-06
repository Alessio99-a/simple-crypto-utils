import { createHmac } from "crypto";

export function hashHmac(data: string, secret: string): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}
