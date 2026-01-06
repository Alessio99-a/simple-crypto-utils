import { createHmac, timingSafeEqual } from "crypto";

export function verifyHmac(
  data: string,
  secret: string,
  expectedHex: string
): boolean {
  const actual = createHmac("sha256", secret).update(data).digest();

  const expected = Buffer.from(expectedHex, "hex");

  if (actual.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(actual, expected);
}
