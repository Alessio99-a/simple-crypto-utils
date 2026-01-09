import { createECDH } from "crypto";

export function generateECDHKeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();

  const publicKey = ecdh.getPublicKey("base64");
  const privateKey = ecdh.getPrivateKey("base64");

  return { publicKey, privateKey };
}
