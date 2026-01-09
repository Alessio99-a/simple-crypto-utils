/**
 * Generate a TOTP code (RFC 6238) using only Node.js crypto
 * @param secret Shared secret (string, base32 or raw)
 * @param digits Number of digits in OTP (default 6)
 * @param period Time step in seconds (default 30)
 * @param timestamp Optional timestamp (defaults to current time)
 * @returns TOTP code as string
 */
export declare function generateTOTP(secret: string, digits?: number, period?: number, timestamp?: number): string;
//# sourceMappingURL=TOTP.d.ts.map