console.log("1. Starting test");
import Signer from "./signature";
import { generateRSAKeyPair } from "./crypto-asymmetricaly/keys/generateRSA";
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);
// const inputPath = path.join(__dirname, "../test.txt");
// const outputPath = path.join(__dirname, "../test.enc");
// const thridPath = path.join(__dirname, "../decrypted.txt");
async function test() {
    console.log("2. Inside test function");
    const { publicKey, privateKey } = await generateRSAKeyPair();
    console.log("3. Generated keys");
    const signer = new Signer({
        strategy: "canonical",
        algorithm: "SHA256",
    });
    console.log("4. Created signer");
    const sign = signer.sign("erbert", privateKey);
    console.log("5. Signed data:", sign);
    const verify = signer.verify("erbert", sign, publicKey);
    console.log("6. Verify result:", verify);
}
console.log("7. About to call test()");
test();
console.log("8. Called test()");
//compila
//npx tsc
//esegui
//node dist/test.js
/*
npx tsx src/test.ts
*/
//# sourceMappingURL=test.js.map