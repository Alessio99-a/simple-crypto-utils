import { decrypt } from "./crypto/decrypt";
import { doubleRatchetTest } from "./crypto/doubleRatchetTest";
import { encrypt } from "./crypto/encrypt";
import { Key } from "./keys";
import { sign, verify } from "./signature";

async function test() {
  // === SETUP: Alice e Bob generano le loro chiavi ===
  const aliceKeys = await Key.generate("channel");
  const bobKeys = await Key.generate("channel");

  console.log("👩 Alice (recipient):", {
    public: aliceKeys.publicKey,
    private: aliceKeys.privateKey?.substring(0, 20) + "...",
  });

  console.log("👨 Bob (sender) - not needed for this mode");

  // === Bob invia un messaggio ad Alice ===
  console.log("\n📤 Bob encrypts message for Alice...");
  const encrypted = await encrypt(
    {
      type: "secure-channel",
      recipientPublicKey: aliceKeys.publicKey as string, // Bob usa la public key di Alice
    },
    "Ciao Alice, questo è un messaggio segreto!"
  );

  console.log("✅ Encrypted:", encrypted.data?.substring(0, 50) + "...");

  // === Alice riceve e decripta il messaggio ===
  console.log("\n📥 Alice decrypts message...");
  const decrypted = await decrypt(
    {
      type: "secure-channel",
      recipientPrivateKey: aliceKeys.privateKey as string, // Alice usa la sua private key
    },
    encrypted.data!
  );

  console.log("✅ Decrypted:", decrypted);

  // === Test: Bob NON può decriptare (non ha la private key di Alice) ===
  console.log("\n❌ Bob tries to decrypt (should fail)...");
  try {
    await decrypt(
      {
        type: "secure-channel",
        recipientPrivateKey: bobKeys.privateKey as string, // Chiave sbagliata!
      },
      encrypted.data!
    );
  } catch (error) {
    console.log("❌ Failed as expected:", (error as Error).message);
  }
}
test();
//compila
//npx tsc
//esegui
//node dist/test.js

/*
npx tsx src/test.ts 
npx tsx src/test.ts --verbose
*/

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// const inputPath = path.join(__dirname, "../test.txt");
// const outputPath = path.join(__dirname, "../test.enc");
// const thridPath = path.join(__dirname, "../decrypted.txt");
