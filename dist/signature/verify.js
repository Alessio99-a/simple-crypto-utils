import { createVerify, createHash } from "crypto";
import { serialize } from "./serialize";
export function verify(data, signature, publicKey, options) {
    const opts = {
        strategy: options?.strategy ?? "canonical",
        fields: options?.fields ?? [],
        algorithm: options?.algorithm ?? "SHA256",
        encoding: options?.encoding ?? "base64",
        preHash: options?.preHash ?? false,
    };
    const serialized = serialize(data, opts.strategy, opts.fields);
    let dataToVerify;
    if (opts.preHash) {
        dataToVerify = createHash(opts.algorithm.toLowerCase())
            .update(serialized)
            .digest();
    }
    else {
        dataToVerify = serialized;
    }
    const verifier = createVerify(opts.algorithm);
    verifier.update(dataToVerify);
    verifier.end();
    return verifier.verify(publicKey, signature, opts.encoding);
}
//# sourceMappingURL=verify.js.map