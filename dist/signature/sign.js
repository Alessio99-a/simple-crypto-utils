import { createSign, createHash } from "crypto";
import { serialize } from "./serialize";
export function sign(data, privateKey, options) {
    const opts = {
        strategy: options?.strategy ?? "canonical",
        fields: options?.fields ?? [],
        algorithm: options?.algorithm ?? "SHA256",
        encoding: options?.encoding ?? "base64",
        preHash: options?.preHash ?? false,
    };
    const serialized = serialize(data, opts.strategy, opts.fields);
    let dataToSign;
    if (opts.preHash) {
        dataToSign = createHash(opts.algorithm.toLowerCase())
            .update(serialized)
            .digest();
    }
    else {
        dataToSign = serialized;
    }
    const signer = createSign(opts.algorithm);
    signer.update(dataToSign);
    signer.end();
    return signer.sign(privateKey, opts.encoding);
}
//# sourceMappingURL=sign.js.map