import elliptic from "elliptic";
import crypto from "crypto";
import fs from "fs";

const EC = elliptic.ec;

const sha256 = (input) => {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
};

const toBase64Url = (str) => {
  const b64 = Buffer.from(str, "utf8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const signPayloadWithApiKey = (payload, apiPrivateKey, apiPublicKey) => {
  const ec = new EC("p256");
  const key = ec.keyFromPrivate(apiPrivateKey, "hex");
  const hashHex = sha256(payload);
  const sig = key.sign(hashHex, { canonical: true });
  const derHex = sig.toDER("hex");

  const stampObj = {
    publicKey: apiPublicKey,
    scheme: "SIGNATURE_SCHEME_TK_API_P256",
    signature: derHex,
  };

  return toBase64Url(JSON.stringify(stampObj));
};

// Main
const payload = process.argv[2];

if (!payload) {
  console.error('Usage: node sign_custom.js \'{"your":"payload"}\'');
  process.exit(1);
}

const privateKey = fs.readFileSync("session_private_key.hex", "utf8").trim();
const ec = new EC("p256");
const publicKey = ec.keyFromPrivate(privateKey, "hex").getPublic(true, "hex");

const signature = signPayloadWithApiKey(payload, privateKey, publicKey);

console.log("Payload:", payload);
console.log("Signature:", signature);
