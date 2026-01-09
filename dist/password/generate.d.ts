export interface PasswordOptions {
    length?: number;
    hash?: boolean;
    letters?: boolean;
    numbers?: boolean;
    symbols?: boolean;
}
export declare function generate(length?: number): string;
export declare function generate(options: PasswordOptions & {
    hash?: false;
}): string;
export declare function generate(options: PasswordOptions & {
    hash: true;
}): Promise<string>;
//# sourceMappingURL=generate.d.ts.map