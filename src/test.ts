import { generateRSAKeyPair } from "./crypt-asimetricaly";
import { encryptString } from "./crypt-asimetricaly";
import { decryptString } from "./crypt-asimetricaly";

async function test() {
  const { publicKey, privateKey } = await generateRSAKeyPair();
  const message = "Hello hybrid encryption!";
  const encrypted = encryptString(message, publicKey);
  const decrypted = decryptString(
    encrypted.encryptedData,
    encrypted.encryptedKey,
    encrypted.iv,
    encrypted.authTag,
    privateKey
  );
  console.log("Decrypted:", decrypted);
}
test();
//compila
//npx tsc
//esegui
//node dist/test.js

/*
npx tsx src/test.ts 
*/
