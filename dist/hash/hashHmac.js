import { createHmac } from "crypto";
export function hashHmac(data, secret) {
    return createHmac("sha256", secret).update(data).digest("hex");
}
//# sourceMappingURL=hashHmac.js.map