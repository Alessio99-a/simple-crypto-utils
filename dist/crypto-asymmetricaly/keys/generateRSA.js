import { generateKeyPair } from "crypto";
export function generateRSAKeyPair() {
    return new Promise((resolve, reject) => {
        generateKeyPair("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: "spki",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem",
            },
        }, (err, publicKey, privateKey) => {
            if (err)
                return reject(err);
            resolve({
                publicKey,
                privateKey,
            });
        });
    });
}
//# sourceMappingURL=generateRSA.js.map