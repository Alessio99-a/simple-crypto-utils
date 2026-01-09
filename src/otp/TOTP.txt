import { createHmac } from "crypto";

/**
 * Generate a TOTP code (RFC 6238) using only Node.js crypto
 * @param secret Shared secret (string, base32 or raw)
 * @param digits Number of digits in OTP (default 6)
 * @param period Time step in seconds (default 30)
 * @param timestamp Optional timestamp (defaults to current time)
 * @returns TOTP code as string
 */
export function generateTOTP(
  secret: string,
  digits: number = 6,
  period: number = 30,
  timestamp: number = Date.now()
): string {
  // 1️⃣ Convert secret to a buffer (we assume UTF-8 for simplicity)
  const key = Buffer.from(secret, "utf8");

  // 2️⃣ Calculate time counter (number of periods since epoch)
  const counter = Math.floor(timestamp / 1000 / period);

  // 3️⃣ Convert counter to 8-byte buffer (big-endian)
  const buffer = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    buffer[i] = counter & 0xff;
    counter >>>= 8;
  }

  // 4️⃣ HMAC-SHA1 of counter using the secret
  const hmac = createHmac("sha1", key).update(buffer).digest();

  // 5️⃣ Dynamic truncation to get a 4-byte string
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // 6️⃣ Reduce to requested number of digits
  const otp = (code % 10 ** digits).toString().padStart(digits, "0");

  return otp;
}
