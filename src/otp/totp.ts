import { createHmac } from "crypto";

/**
 * Converts a Base32-encoded string into a Buffer.
 *
 * @param base32 - The Base32 string to convert.
 * @returns A Buffer containing the decoded bytes.
 */
function base32ToBuffer(base32: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let bytes: number[] = [];

  base32 = base32.replace(/=+$/, "").toUpperCase();

  for (const char of base32) {
    const val = alphabet.indexOf(char);
    bits += val.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

/**
 * Generates a Time-based One-Time Password (TOTP) according to RFC 6238.
 *
 * @param secret - The shared secret in Base32 encoding.
 * @param digits - Number of digits in the OTP (default: 6).
 * @param period - Time step in seconds (default: 30).
 * @param timestamp - Unix timestamp in milliseconds (default: current time).
 * @returns A numeric OTP as a string, zero-padded to the specified length.
 *
 * @example
 * ```ts
 * import { generateTOTP } from "./totp";
 *
 * const secret = "JBSWY3DPEHPK3PXP"; // Base32 secret
 * const otp = generateTOTP(secret);
 * console.log(otp); // e.g., "492039"
 *
 * // Generate a 8-digit OTP with a 60-second period
 * const otp8 = generateTOTP(secret, 8, 60);
 * console.log(otp8);
 * ```
 */
export function generateTOTP(
  secret: string,
  digits = 6,
  period = 30,
  timestamp = Date.now()
): string {
  const key = base32ToBuffer(secret);

  let counter = Math.floor(timestamp / 1000 / period);

  const buffer = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    buffer[i] = counter & 0xff;
    counter >>= 8;
  }

  const hmac = createHmac("sha1", key).update(buffer).digest();

  const offset = hmac[hmac.length - 1]! & 0xf;

  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return (code % 10 ** digits).toString().padStart(digits, "0");
}
