import { generateKeyPairSync } from "crypto";

/**
 * Genera una coppia di chiavi X25519
 */
export function generateECDHKeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");

  return {
    publicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    privateKey: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
  };
}

//OLD
// export function generateECDHKeyPair(): {
//   publicKey: string;
//   privateKey: string;
// } {
//   const ecdh = createECDH("prime256v1");
//   ecdh.generateKeys();

//   const publicKey = ecdh.getPublicKey("base64");
//   const privateKey = ecdh.getPrivateKey("base64");

//   return { publicKey, privateKey };
// }
