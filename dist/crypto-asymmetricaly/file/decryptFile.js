import { createReadStream, createWriteStream } from "fs";
import { createDecipheriv, privateDecrypt, constants } from "crypto";
import { pipeline } from "stream/promises";
import { open } from "fs/promises";
export async function decryptFile(inputPath, outputPath, privateKey) {
    // 1️⃣ Open file handle (doesn't load into memory)
    const fileHandle = await open(inputPath, "r");
    try {
        // 2️⃣ Read only the first 4 bytes to get header length
        const headerLengthBuf = Buffer.alloc(4);
        const { bytesRead: lengthBytesRead } = await fileHandle.read(headerLengthBuf, 0, 4, 0);
        if (lengthBytesRead < 4) {
            throw new Error(`File is too small (${lengthBytesRead} bytes). Expected at least 4 bytes for header length.`);
        }
        const headerLength = headerLengthBuf.readUInt32BE(0);
        console.log("Header length:", headerLength);
        // 3️⃣ Validate header length is reasonable
        if (headerLength > 10000) {
            throw new Error(`Header length suspiciously large (${headerLength} bytes). File may be corrupted.`);
        }
        // 4️⃣ Read only the header (not the entire file!)
        const headerBuf = Buffer.alloc(headerLength);
        const { bytesRead: headerBytesRead } = await fileHandle.read(headerBuf, 0, headerLength, 4);
        if (headerBytesRead < headerLength) {
            throw new Error(`File is too short to contain the header. Expected ${headerLength} bytes, got ${headerBytesRead}`);
        }
        // 5️⃣ Parse header JSON
        const headerJson = headerBuf.toString("utf8");
        console.log("Header JSON:", headerJson);
        let header;
        try {
            header = JSON.parse(headerJson);
        }
        catch (e) {
            throw new Error(`Failed to parse header JSON: ${e}`);
        }
        // 6️⃣ Validate header fields
        if (!header.encryptedKey || !header.iv || !header.authTag) {
            throw new Error("Invalid header: missing required fields");
        }
        // 7️⃣ Extract buffers from base64
        const encryptedKeyBuf = Buffer.from(header.encryptedKey, "base64");
        const iv = Buffer.from(header.iv, "base64");
        const authTag = Buffer.from(header.authTag, "base64");
        console.log("Encrypted key length:", encryptedKeyBuf.length);
        console.log("IV length:", iv.length);
        console.log("Auth tag length:", authTag.length);
        // 8️⃣ Validate buffer sizes
        if (iv.length !== 12) {
            throw new Error(`Invalid IV length: expected 12 bytes, got ${iv.length}`);
        }
        if (authTag.length !== 16) {
            throw new Error(`Invalid auth tag length: expected 16 bytes, got ${authTag.length}`);
        }
        // 9️⃣ Decrypt AES key with RSA private key
        let aesKey;
        try {
            aesKey = privateDecrypt({
                key: privateKey,
                padding: constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            }, encryptedKeyBuf);
        }
        catch (e) {
            throw new Error(`Failed to decrypt AES key: ${e}`);
        }
        // Validate AES key length
        if (aesKey.length !== 32) {
            throw new Error(`Invalid AES key length: expected 32 bytes, got ${aesKey.length}`);
        }
        // 🔟 Create decipher
        const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
        decipher.setAuthTag(authTag);
        // 1️⃣1️⃣ Stream encrypted content (after header) → decipher → output
        // This streams the data, never loading the full file into memory
        const inputStream = createReadStream(inputPath, {
            start: 4 + headerLength,
        });
        const outputStream = createWriteStream(outputPath);
        try {
            await pipeline(inputStream, decipher, outputStream);
            console.log("✅ File decrypted successfully");
        }
        catch (e) {
            throw new Error(`Decryption failed (authentication error): ${e}`);
        }
    }
    finally {
        // Always close the file handle
        await fileHandle.close();
    }
}
//# sourceMappingURL=decryptFile.js.map