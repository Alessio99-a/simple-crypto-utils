import { randomBytes, scryptSync } from "crypto";
import { generateTOTP } from "./otp/totp";
import { generate } from "./password";
async function test() {
  const pwd = generate();
  console.log(pwd);
  const salt = randomBytes(16);
  const hashed = scryptSync(pwd, salt, 32);
  console.log(hashed.toString("base64"));
  const totp = generateTOTP(hashed.toString("base64"));
  console.log(totp);
}

test();
/*
npx tsx src/test.ts 
npx tsx src/examples.ts 
npx tsx src/test.ts --verbose
*/
