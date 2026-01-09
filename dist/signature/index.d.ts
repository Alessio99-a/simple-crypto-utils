import type { SignOptions, VerifyOptions } from "./types";
export declare class Signer {
    private defaultOptions;
    constructor(defaultOptions?: Partial<SignOptions>);
    /**
     * Sign data with private key
     */
    sign(data: any, privateKey: string, options?: SignOptions): string;
    /**
     * Verify signature with public key
     */
    verify(data: any, signature: string, publicKey: string, options?: VerifyOptions): boolean;
    /**
     * Create a signed envelope (data + signature)
     */
    envelope(data: any, privateKey: string, options?: SignOptions): {
        data: any;
        signature: string;
    };
    /**
     * Verify and extract data from signed envelope
     */
    openEnvelope(envelope: {
        data: any;
        signature: string;
    }, publicKey: string, options?: VerifyOptions): {
        valid: boolean;
        data: any;
    };
}
export { Signer as default };
export { sign } from "./sign";
export { verify } from "./verify";
export type { SignOptions, VerifyOptions, SerializationStrategy, } from "./types";
export declare const envelope: (data: any, privateKey: string, options?: SignOptions) => {
    data: any;
    signature: string;
};
export declare const openEnvelope: (envelope: {
    data: any;
    signature: string;
}, publicKey: string, options?: VerifyOptions) => {
    valid: boolean;
    data: any;
};
//# sourceMappingURL=index.d.ts.map