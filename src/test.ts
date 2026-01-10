import { decrypt } from "./crypto/decrypt";
import { encrypt } from "./crypto/encrypt";
import { Key } from "./keys";
import { sign, verify } from "./signature";

/*
 Key {
  publicKey: 'BHaHij3c2Yuyk4Ko3h6FhDWrrI7OMg1LWV+xxUYJnXLllEoMNyXly77azbKP189Y5RJJw8QDQZZHYKtYk6q81ws=',
  privateKey: 'L+m9FVhfWryoPVqzDS4eRpJJKykJz/55t0FSoCt2cos='
}*/
async function test() {
  const newKeys = await Key.generate("sign");
  console.log(newKeys);

  const singedData = sign("john", newKeys.privateKey as string);
  const verifiedData = verify("john", singedData, newKeys.publicKey as string);
  console.log(singedData);
  console.log(verifiedData);
  // ✅ Encrypt with consistent parameter order
  // const encrypted1 = await encrypt(
  //   {
  //     type: "secure-channel",
  //     recipientPublicKey:
  //       "BHaHij3c2Yuyk4Ko3h6FhDWrrI7OMg1LWV+xxUYJnXLllEoMNyXly77azbKP189Y5RJJw8QDQZZHYKtYk6q81ws=",
  //   },
  //   "Hello World"
  // );

  // // ✅ Decrypt
  // const decrypted1 = await decrypt(
  //   {
  //     type: "secure-channel",
  //     recipientPrivateKey:
  //       "L+m9FVhfWryoPVqzDS4eRpJJKykJz/55t0FSoCt2cos=" as string,
  //   },
  //   encrypted1.data!
  // );
  // console.log(decrypted1.data); // "Hello World"

  // // ✅ Encrypt an object
  // const encrypted2 = await encrypt(
  //   {
  //     type: "secure-channel",
  //     recipientPublicKey:
  //       "BHaHij3c2Yuyk4Ko3h6FhDWrrI7OMg1LWV+xxUYJnXLllEoMNyXly77azbKP189Y5RJJw8QDQZZHYKtYk6q81ws=",
  //   },
  //   { user: "Alice", age: 30 }
  // );

  // // ✅ Decrypt
  // const decrypted2 = await decrypt(
  //   {
  //     type: "secure-channel",
  //     recipientPrivateKey:
  //       "L+m9FVhfWryoPVqzDS4eRpJJKykJz/55t0FSoCt2cos=" as string,
  //   },
  //   encrypted2.data!
  // );
  // console.log(decrypted2.data); // { user: "Alice", age: 30 }

  // // ✅ File encryption/decryption
  // await encrypt(
  //   { type: "symmetric-password", password: "secret" },
  //   Buffer.from(""), // dummy buffer for file mode
  //   "./input.txt",
  //   "./encrypted.bin"
  // );

  // await decrypt(
  //   { type: "symmetric-password", password: "secret" },
  //   "", // dummy string for file mode
  //   "./encrypted.bin",
  //   "./decrypted.txt"
  // );
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
