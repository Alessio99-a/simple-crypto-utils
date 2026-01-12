import { generateRSAKeyPair } from "./rsa";
import { generateEd25519KeyPair } from "./ed25519";
import { generateX25519KeyPair } from "./x25519";
import { generateAuthenticatedKeySet } from "./authenticated";
export type keyType =
  | "seal"
  | "sign"
  | "secure-channel"
  | "authenticated-channel";

export class Key {
  publicKey?: string;
  privateKey?: string;
  signingPublicKey?: string;
  signingPrivateKey?: string;

  static async generate(key: keyType): Promise<Key> {
    const k = new Key(); // create instance inside
    switch (key) {
      case "authenticated-channel": {
        const key = generateAuthenticatedKeySet();
        k.publicKey = key.encryption.publicKey;
        k.privateKey = key.encryption.privateKey;
        k.signingPublicKey = key.signing.publicKey;
        k.signingPrivateKey = key.signing.privateKey;
        break;
      }
      case "secure-channel": {
        const { publicKey, privateKey } = generateX25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }
      case "seal": {
        const { publicKey, privateKey } = await generateRSAKeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }

      case "sign": {
        const { publicKey, privateKey } = generateEd25519KeyPair();
        k.publicKey = publicKey;
        k.privateKey = privateKey;
        break;
      }

      default:
        throw new Error(`Unknown key type: ${key}`);
    }
    return k; // return the new instance
  }
}

export { generateECDHKeyPair } from "./ecdh";
export { generateRSAKeyPair } from "./rsa";
