import { randomBytes } from "crypto";
export function generateOtp(length = 6) {
    const max = 10 ** length;
    const randomNumber = parseInt(randomBytes(4).toString("hex"), 16) % max;
    return randomNumber.toString().padStart(length, "0");
}
//# sourceMappingURL=generate.js.map