import { createHash } from "crypto";
export function hash(data) {
    const hash = createHash("sha256");
    hash.update(data);
    return hash.digest("hex");
}
//# sourceMappingURL=hash.js.map