import { randomBytes } from "crypto";
export function generatePassword(lenght = 256) {
    randomBytes(lenght, (err, buf) => {
        if (err)
            throw err;
        console.log(`${buf.length} bytes of random data: ${buf.toString("hex")}`);
    });
    return "q";
}
//# sourceMappingURL=generatePassword.js.map