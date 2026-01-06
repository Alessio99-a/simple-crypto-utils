import { randomBytes } from "crypto";

export function generateOtp(length: number = 6): string {
  const max = 10 ** length;
  const randomNumber = parseInt(randomBytes(4).toString("hex"), 16) % max;
  return randomNumber.toString().padStart(length, "0");
}
