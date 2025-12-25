import elliptic from "elliptic";
import fs from "fs";

const EC = elliptic.ec;
const ec = new EC("p256");

const keyPair = ec.genKeyPair();

// Get COMPRESSED public key (66 hex chars, starts with 0x02 or 0x03)
const compressedPublicKey = keyPair.getPublic(true, "hex");

// Get private key (64 hex chars)
const privateKeyHex = keyPair.getPrivate("hex").padStart(64, "0");

// Save both
fs.writeFileSync("private.hex", privateKeyHex);
fs.writeFileSync("public_compressed.hex", compressedPublicKey);

console.log("Private key (64 chars):", privateKeyHex);
console.log("Compressed Public key (66 chars):", compressedPublicKey);
console.log("Public key prefix:", compressedPublicKey.slice(0, 2));

// Use this compressed public key in your register-auth API:
console.log("\nUse this public key in register-auth API:");
console.log(compressedPublicKey);
