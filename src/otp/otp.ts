import { randomBytes } from "crypto";

/**
 * Generates a numeric one-time password (OTP) of a specified length.
 *
 * The OTP consists only of digits (0–9) and is padded with leading zeros
 * if necessary.
 *
 * @param length - The length of the OTP (default: 6). Must be a positive integer.
 * @returns A string representing the numeric OTP.
 *
 * @example
 * ```ts
 * import { generateOTP } from "./otp";
 *
 * const otp = generateOTP();       // e.g., "084321"
 * const otp8 = generateOTP(8);     // e.g., "09238475"
 *
 * console.log(otp, otp8);
 * ```
 */
export function generateOTP(length: number = 6): string {
  const max = 10 ** length;

  // Generate 4 random bytes (32 bits) and convert to integer
  const randomNumber = parseInt(randomBytes(4).toString("hex"), 16) % max;

  // Pad with leading zeros if needed
  return randomNumber.toString().padStart(length, "0");
}
