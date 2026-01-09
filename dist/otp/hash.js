import { createHash } from "crypto";
export function hashOtp(otp) {
    return createHash("sha256").update(otp).digest("hex");
}
//# sourceMappingURL=hash.js.map