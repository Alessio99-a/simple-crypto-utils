import { scryptSync, createDecipheriv, } from "crypto";
// Decrypt
export function decrypt(encHex, password) {
    const data = Buffer.from(encHex, "hex");
    const salt = data.subarray(0, 16);
    const iv = data.subarray(16, 28);
    const tag = data.subarray(28, 44);
    const encrypted = data.subarray(44);
    const key = scryptSync(password, salt, 32);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}
//# sourceMappingURL=decrypt.js.map