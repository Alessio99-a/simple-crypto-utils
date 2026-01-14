import { Key } from "./keys";
import Signer from "./signature";
async function test() {
  const keys = await Key.generate("sign");
  const clas = Signer;

  const sign = clas.envelope("erbert", keys.privateKey as string);
  const verif = clas.openEnvelope(
    { data: sign.data, signature: sign.signature },
    keys.publicKey as string
  );
  console.log(sign, verif);
}

test();
/*
npx tsx src/test.ts 
npx tsx src/examples.ts 
npx tsx src/test.ts --verbose
*/
