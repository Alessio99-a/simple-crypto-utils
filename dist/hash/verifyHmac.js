import { createHmac, timingSafeEqual } from "crypto";
export function verifyHmac(data, secret, expectedHex) {
    const actual = createHmac("sha256", secret).update(data).digest();
    const expected = Buffer.from(expectedHex, "hex");
    if (actual.length !== expected.length) {
        return false;
    }
    return timingSafeEqual(actual, expected);
}
//# sourceMappingURL=verifyHmac.js.map