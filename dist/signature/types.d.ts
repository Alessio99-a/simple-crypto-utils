export type SerializationStrategy = "canonical" | "raw" | "selective";
export interface SignOptions {
    /** Serialization strategy for complex objects */
    strategy?: SerializationStrategy;
    /** Fields to sign when using 'selective' strategy */
    fields?: string[];
    /** Hash algorithm (default: 'SHA256') */
    algorithm?: "SHA256" | "SHA384" | "SHA512";
    /** Output encoding (default: 'base64') */
    encoding?: "base64" | "hex";
    /** Pre-hash large data before signing (recommended for >1MB) */
    preHash?: boolean;
}
export interface VerifyOptions extends SignOptions {
}
//# sourceMappingURL=types.d.ts.map