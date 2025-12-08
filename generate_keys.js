import elliptic from "elliptic";
import fs from "fs";

const EC = elliptic.ec;
const ec = new EC("p256");

const keyPair = ec.genKeyPair();

const uncompressedPublicKey = keyPair.getPublic(false, "hex");
const privateKeyHex = keyPair.getPrivate("hex").padStart(64, "0");

fs.writeFileSync("ephemeral_private.hex", privateKeyHex);
fs.writeFileSync("ephemeral_public.hex", uncompressedPublicKey);

console.log("Private key saved to: ephemeral_private.hex");
console.log("Public key saved to: ephemeral_public.hex");
console.log("");
console.log("Private key length:", privateKeyHex.length, "hex chars");
console.log("Public key length:", uncompressedPublicKey.length, "hex chars");
console.log("Public key prefix:", uncompressedPublicKey.slice(0, 2));
console.log("");
console.log("Use this public key in start-session API:");
console.log(uncompressedPublicKey);
