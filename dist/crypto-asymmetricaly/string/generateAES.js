import { randomBytes } from "crypto";
export function generateAESKey() {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    return { key, iv };
}
//# sourceMappingURL=generateAES.js.map