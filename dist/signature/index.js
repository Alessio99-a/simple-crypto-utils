import { sign as signFunction } from "./sign";
import { verify as verifyFunction } from "./verify";
export class Signer {
    constructor(defaultOptions) {
        this.defaultOptions = {
            strategy: defaultOptions?.strategy ?? "canonical",
            fields: defaultOptions?.fields ?? [],
            algorithm: defaultOptions?.algorithm ?? "SHA256",
            encoding: defaultOptions?.encoding ?? "base64",
            preHash: defaultOptions?.preHash ?? false,
        };
    }
    /**
     * Sign data with private key
     */
    sign(data, privateKey, options) {
        const opts = { ...this.defaultOptions, ...options };
        return signFunction(data, privateKey, opts);
    }
    /**
     * Verify signature with public key
     */
    verify(data, signature, publicKey, options) {
        const opts = { ...this.defaultOptions, ...options };
        return verifyFunction(data, signature, publicKey, opts);
    }
    /**
     * Create a signed envelope (data + signature)
     */
    envelope(data, privateKey, options) {
        return {
            data,
            signature: this.sign(data, privateKey, options),
        };
    }
    /**
     * Verify and extract data from signed envelope
     */
    openEnvelope(envelope, publicKey, options) {
        const valid = this.verify(envelope.data, envelope.signature, publicKey, options);
        return { valid, data: envelope.data };
    }
}
// Export class
export { Signer as default };
export { sign } from "./sign";
export { verify } from "./verify";
const defaultSigner = new Signer();
export const envelope = defaultSigner.envelope.bind(defaultSigner);
export const openEnvelope = defaultSigner.openEnvelope.bind(defaultSigner);
//# sourceMappingURL=index.js.map