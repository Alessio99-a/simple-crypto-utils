import { randomBytes } from "crypto";
const charsetMap = {
    letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    numbers: "0123456789",
    symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};
// Implementation
export function generate(lengthOrOptions) {
    let length = 16;
    let hash = false;
    let letters = true;
    let numbers = true;
    let symbols = true;
    if (typeof lengthOrOptions === "number") {
        length = lengthOrOptions;
    }
    else if (typeof lengthOrOptions === "object") {
        length = lengthOrOptions.length ?? 16;
        hash = lengthOrOptions.hash ?? false;
        letters = lengthOrOptions.letters ?? true;
        numbers = lengthOrOptions.numbers ?? true;
        symbols = lengthOrOptions.symbols ?? true;
    }
    let charset = "";
    if (letters)
        charset += charsetMap.letters;
    if (numbers)
        charset += charsetMap.numbers;
    if (symbols)
        charset += charsetMap.symbols;
    if (charset.length === 0) {
        charset = Object.values(charsetMap).join("");
    }
    if (length < 1 || length > 1024) {
        throw new Error("Length must be between 1 and 1024");
    }
    const bytes = randomBytes(length);
    const password = Array.from(bytes, (byte) => charset[byte % charset.length]).join("");
    // if (hash) {
    //   return hash(password);
    // }
    return password;
}
//# sourceMappingURL=generate.js.map