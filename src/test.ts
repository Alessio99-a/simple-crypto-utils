import { generateRSAKeyPair } from "./crypt-asimetricaly";
import { encryptString } from "./crypt-asimetricaly";
import { decryptString } from "./crypt-asimetricaly";
import { encryptFile } from "./crypt-asimetricaly/file/encryptFile";
import * as path from "path";
import { fileURLToPath } from "url";
import { decryptFile } from "./crypt-asimetricaly/file/decryptFile";
import { randomFillSync } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const inputPath = path.join(__dirname, "../test.txt"); // points to root
const outputPath = path.join(__dirname, "../test.enc"); // output file in root
const thridPath = path.join(__dirname, "../decrypted.txt");
async function test() {
  const { publicKey, privateKey } = await generateRSAKeyPair();

  const file = await encryptFile(inputPath, outputPath, publicKey);
  //console.log(privateKey);
  const decrypt = decryptFile(outputPath, thridPath, privateKey);
}
test();
//compila
//npx tsc
//esegui
//node dist/test.js

/*
npx tsx src/test.ts 
*/
