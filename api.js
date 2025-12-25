// sign-payload.js
import elliptic from "elliptic";
import fs from "fs";
import crypto from "crypto";
const EC = elliptic.ec;

// SHA-256 hashing function (Node.js)
const sha256 = (input) => {
  return crypto.createHash("sha256").update(input).digest("hex");
};

// Base64URL encoding
const toBase64Url = (str) => {
  const b64 = Buffer.from(str).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Load your keys
const privateKeyHex = fs.readFileSync("ephemeral_private.hex", "utf-8").trim();
const compressedPublicKey = fs
  .readFileSync("ephemeral_public_compressed.hex", "utf-8")
  .trim();

// Initialize elliptic curve
const ec = new EC("p256");

// Create key object
const key = ec.keyFromPrivate(privateKeyHex, "hex");

// Verify key pair matches
const derivedPublicKey = key.getPublic(true, "hex");
if (derivedPublicKey !== compressedPublicKey) {
  console.error("❌ ERROR: Public key doesn't match private key!");
  console.log("Expected:", compressedPublicKey);
  console.log("Derived:", derivedPublicKey);
  process.exit(1);
}

// Your API response
const apiResponse = {
  success: true,
  data: {
    payloadId: "auth_e0ac8b2c_2102_4b39_91d6_33de38a80ea0",
    payloadToSign:
      '{"parameters":{"accounts":[{"addressFormat":"ADDRESS_FORMAT_SOLANA","curve":"CURVE_ED25519","path":"m/44\'/501\'/0\'/0\'","pathFormat":"PATH_FORMAT_BIP32"}],"walletName":"My SOLANA"},"organizationId":"02b40989-cc11-4a45-ae11-304aac8d320b","type":"ACTIVITY_TYPE_CREATE_WALLET","timestampMs":"1766690726444"}',
    rpId: "backend_base_url",
  },
};

const signPayload = () => {
  try {
    const payloadToSign = apiResponse.data.payloadToSign;
    const payloadId = apiResponse.data.payloadId;

    console.log("📝 Signing payload for wallet creation...");
    console.log("Payload ID:", payloadId);
    console.log("\nPayload to sign:", payloadToSign);

    // Hash the payload
    const hashHex = sha256(payloadToSign);
    console.log("\n🔐 SHA-256 hash:", hashHex);

    // Sign the hash
    const signature = key.sign(hashHex, { canonical: true });

    // Encode to DER format
    const derHex = signature.toDER("hex");
    console.log("\n✍️ DER-encoded signature:", derHex);
    console.log("DER length:", derHex.length, "hex chars");

    // Construct signature object
    const stampObj = {
      publicKey: compressedPublicKey,
      scheme: "SIGNATURE_SCHEME_TK_API_P256",
      signature: derHex,
    };

    // Base64URL encode
    const finalSignature = toBase64Url(JSON.stringify(stampObj));

    console.log("\n" + "=".repeat(60));
    console.log("✅ SIGNATURE GENERATED SUCCESSFULLY");
    console.log("=".repeat(60));

    console.log("\n📤 Use this in your wallet creation request:");
    console.log("\n1. Headers:");
    console.log(`   x-api-token: your_api_token_here`);
    console.log(`   x-signature: ${finalSignature}`);

    console.log("\n2. Request body should include:");
    console.log(`   "payloadId": "${payloadId}"`);
    console.log(`   "signedPayload": "${payloadToSign}"`); // If required

    console.log("\n3. Signature details:");
    console.log(`   • Public Key: ${compressedPublicKey}`);
    console.log(`   • Scheme: ${stampObj.scheme}`);
    console.log(`   • Payload ID: ${payloadId}`);

    // Verification check
    const verifyKey = ec.keyFromPublic(compressedPublicKey, "hex");
    const isValid = verifyKey.verify(hashHex, signature);
    console.log(
      `\n🔍 Signature self-verification: ${isValid ? "✓ PASS" : "✗ FAIL"}`
    );

    return {
      signature: finalSignature,
      publicKey: compressedPublicKey,
      payloadId: payloadId,
      payloadToSign: payloadToSign,
      isValid: isValid,
    };
  } catch (error) {
    console.error("❌ Error signing payload:", error);
    throw error;
  }
};

// Run it
const result = signPayload();
console.log("\n🎯 Copy the 'x-signature' header value for your API call:");
console.log(result.signature);
