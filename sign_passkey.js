import crypto from "crypto";
import elliptic from "elliptic";
import fs from "fs";
const EC = elliptic.ec;

function generateApiKeySignatureWithLogs(
  payloadToSign,
  privateKeyHex,
  publicKeyHex
) {
  const hashHex = crypto
    .createHash("sha256")
    .update(payloadToSign)
    .digest("hex");

  const ec = new EC("p256");

  const key = ec.keyFromPrivate(privateKeyHex, "hex");

  const derivedPublicKey = key.getPublic(true, "hex");

  if (derivedPublicKey === publicKeyHex) {
    console.log("Keys are a valid pair.");
  } else {
    throw new Error("Public key does not match private key!");
  }

  const signature = key.sign(hashHex, { canonical: true });

  const derHex = signature.toDER("hex");

  const stampObj = {
    publicKey: publicKeyHex,
    scheme: "SIGNATURE_SCHEME_TK_API_P256",
    signature: derHex,
  };

  const jsonString = JSON.stringify(stampObj);

  const base64 = Buffer.from(jsonString).toString("base64");
  const base64Url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  console.log(
    JSON.stringify(
      {
        signature: base64Url,
      },
      null,
      2
    )
  );

  return base64Url;
}

const privateKey = fs.readFileSync("session_private_key.hex", "utf8").trim();
const publicKey = fs.readFileSync("session_public_key.hex", "utf8").trim();

const payload = process.argv[2];

generateApiKeySignatureWithLogs(payload, privateKey, publicKey);
