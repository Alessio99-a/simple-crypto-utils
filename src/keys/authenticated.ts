import { generateX25519KeyPair } from "./x25519";
import { generateEd25519KeyPair } from "./ed25519";

export function generateAuthenticatedKeySet(): {
  encryption: { publicKey: string; privateKey: string };
  signing: { publicKey: string; privateKey: string };
} {
  return {
    encryption: generateX25519KeyPair(),
    signing: generateEd25519KeyPair(),
  };
}
