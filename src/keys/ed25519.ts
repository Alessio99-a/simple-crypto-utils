import { generateKeyPairSync } from "crypto";

export function generateEd25519KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  return {
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  };
}

//OLD
// export function generateECDSAKeyPair() {
//   const { publicKey, privateKey } = generateKeyPairSync("ec", {
//     namedCurve: "prime256v1", // P-256
//     publicKeyEncoding: {
//       type: "spki",
//       format: "pem",
//     },
//     privateKeyEncoding: {
//       type: "pkcs8",
//       format: "pem",
//     },
//   });

//   return { publicKey, privateKey };
// }
