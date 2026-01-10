import { generateECDHKeyPair } from "./ecdh";
import { generateRSAKeyPair } from "./rsa";
import { generateECDSAKeyPair } from "./ecdsa";
export type keyType = "seal" | "sign" | "channel";

export class Key {
  publicKey?: string;
  privateKey?: string;

  static async generate(key: keyType): Promise<Key> {
    const k = new Key(); // create instance inside
    switch (key) {
      case "channel": {
        const { publicKey, privateKey } = generateECDHKeyPair();
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
        const { publicKey, privateKey } = generateECDSAKeyPair();
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
