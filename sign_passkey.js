import elliptic from "elliptic";
import crypto from "crypto";
const EC = elliptic.ec;

function generateApiKeySignatureWithLogs(
  payloadToSign,
  privateKeyHex,
  publicKeyHex
) {
  console.log("\n══════════════════════════════════════════════════");
  console.log("🚀 STARTING SIGNATURE GENERATION FOR PASSPORT REGISTRATION");
  console.log("══════════════════════════════════════════════════\n");

  // ================== STEP 1: LOG INPUTS ==================
  console.log("📝 STEP 1: VERIFYING INPUTS");
  console.log("──────────────────────────────────────────────────");
  console.log("📦 Payload to sign (first 100 chars):");
  console.log(`   "${payloadToSign.substring(0, 100)}..."`);
  console.log(`   Total length: ${payloadToSign.length} characters\n`);

  console.log("🔑 Private Key (first/last 10 chars):");
  console.log(
    `   ${privateKeyHex.substring(0, 10)}...${privateKeyHex.substring(54)}`
  );
  console.log(`   Length: ${privateKeyHex.length} chars (should be 64)\n`);

  console.log("🔐 Public Key (first/last 10 chars):");
  console.log(
    `   ${publicKeyHex.substring(0, 10)}...${publicKeyHex.substring(56)}`
  );
  console.log(`   Length: ${publicKeyHex.length} chars (should be 66)`);
  console.log(
    `   Format: ${
      publicKeyHex.startsWith("02") || publicKeyHex.startsWith("03")
        ? "✅ Compressed (starts with 02/03)"
        : "❌ Not compressed format!"
    }`
  );
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 2: HASHING ==================
  console.log("🔢 STEP 2: CREATING SHA-256 HASH");
  console.log("──────────────────────────────────────────────────");
  const hashHex = crypto
    .createHash("sha256")
    .update(payloadToSign)
    .digest("hex");
  console.log("✅ SHA-256 Hash generated:");
  console.log(`   ${hashHex}`);
  console.log(
    `   Hash length: ${hashHex.length} hex chars (${hashHex.length / 2} bytes)`
  );
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 3: INITIALIZE EC ==================
  console.log("📐 STEP 3: INITIALIZING P-256 ELLIPTIC CURVE");
  console.log("──────────────────────────────────────────────────");
  const ec = new EC("p256");
  console.log("✅ P-256 curve initialized");
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 4: LOAD PRIVATE KEY ==================
  console.log("🗝️ STEP 4: LOADING PRIVATE KEY");
  console.log("──────────────────────────────────────────────────");
  const key = ec.keyFromPrivate(privateKeyHex, "hex");
  console.log("✅ Private key loaded into EC key object");
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 5: VERIFY KEY PAIR ==================
  console.log("✅ STEP 5: VERIFYING KEY PAIR MATCH");
  console.log("──────────────────────────────────────────────────");
  const derivedPublicKey = key.getPublic(true, "hex"); // compressed
  console.log("📤 Derived public key from private key:");
  console.log(
    `   ${derivedPublicKey.substring(0, 10)}...${derivedPublicKey.substring(
      56
    )}`
  );

  if (derivedPublicKey === publicKeyHex) {
    console.log("🎉 ✅ PUBLIC KEY MATCHES! Keys are a valid pair.");
  } else {
    console.log("❌ ⚠️  PUBLIC KEY MISMATCH!");
    console.log("   Expected: ..." + publicKeyHex.substring(56));
    console.log("   Got:      ..." + derivedPublicKey.substring(56));
    throw new Error("Public key does not match private key!");
  }
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 6: SIGN THE HASH ==================
  console.log("✍️ STEP 6: SIGNING HASH WITH ECDSA");
  console.log("──────────────────────────────────────────────────");
  const signature = key.sign(hashHex, { canonical: true });
  console.log("✅ ECDSA Signature created");
  console.log("   Signature components:");
  console.log(`   r = ${signature.r.toString(16)}`);
  console.log(`   s = ${signature.s.toString(16)}`);
  console.log(`   Recovery param: ${signature.recoveryParam}`);
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 7: CONVERT TO DER ==================
  console.log("📄 STEP 7: CONVERTING TO DER FORMAT");
  console.log("──────────────────────────────────────────────────");
  const derHex = signature.toDER("hex");
  console.log("✅ DER-encoded signature:");
  console.log(`   ${derHex.substring(0, 80)}...`);
  console.log(
    `   Total length: ${derHex.length} hex chars (${derHex.length / 2} bytes)`
  );
  console.log("   Typical DER structure:");
  console.log("     30 [total-length] 02 [r-length] [r] 02 [s-length] [s]");
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 8: BUILD SIGNATURE OBJECT ==================
  console.log("🏗️ STEP 8: BUILDING SIGNATURE OBJECT");
  console.log("──────────────────────────────────────────────────");
  const stampObj = {
    publicKey: publicKeyHex,
    scheme: "SIGNATURE_SCHEME_TK_API_P256",
    signature: derHex,
  };

  console.log("📝 Raw signature object:");
  console.log(JSON.stringify(stampObj, null, 2));

  const jsonString = JSON.stringify(stampObj);
  console.log(`\n📏 JSON string length: ${jsonString.length} chars`);
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 9: BASE64URL ENCODE ==================
  console.log("🔣 STEP 9: BASE64URL ENCODING");
  console.log("──────────────────────────────────────────────────");
  const base64 = Buffer.from(jsonString).toString("base64");
  const base64Url = base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  console.log("📊 Base64 (standard):");
  console.log(`   ${base64.substring(0, 80)}...`);
  console.log(`   Length: ${base64.length} chars`);

  console.log("\n🔗 Base64URL (URL-safe):");
  console.log(`   ${base64Url.substring(0, 80)}...`);
  console.log(`   Length: ${base64Url.length} chars`);

  console.log("\n🔍 Character replacements:");
  console.log(
    `   '+' → '-' (${(base64.match(/\+/g) || []).length} replacements)`
  );
  console.log(
    `   '/' → '_' (${(base64.match(/\//g) || []).length} replacements)`
  );
  console.log(`   '=' → removed (padding removed)`);
  console.log("──────────────────────────────────────────────────\n");

  // ================== STEP 10: FINAL OUTPUT ==================
  console.log("🎯 STEP 10: FINAL SIGNATURE");
  console.log("══════════════════════════════════════════════════");
  console.log("✅ SIGNATURE GENERATED SUCCESSFULLY!");
  console.log(`\n📋 Copy this for your Postman request:`);
  console.log("══════════════════════════════════════════════════");
  console.log(base64Url);
  console.log("══════════════════════════════════════════════════");

  // ================== SAMPLE POSTMAN REQUEST ==================
  console.log("\n📮 SAMPLE POSTMAN REQUEST BODY:");
  console.log("══════════════════════════════════════════════════");
  console.log(
    JSON.stringify(
      {
        payloadId: "YOUR_PAYLOAD_ID_FROM_STEP_1", // ← Replace this!
        signature: base64Url,
      },
      null,
      2
    )
  );
  console.log("══════════════════════════════════════════════════\n");

  console.log("📍 REMINDER:");
  console.log(
    '   1. Use this signature in "Submit passkey registration (Step 2)"'
  );
  console.log("   2. Make sure payloadId matches your Step 1 response");
  console.log("   3. Header x-api-token is still required");

  return base64Url;
}

const examplePayload =
  '{"type":"ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2","organizationId":"b45ddbce-ff77-4f85-b856-f4e28938b51a","timestampMs":"1765216761957","parameters":{"userId":"a77b66bc-0610-4f68-a895-6ec556aee48d","authenticators":[{"authenticatorName":"Platform Authenticator","challenge":"&#x2F;uOsBILcFcNDgskynUzzX+lSIiiV1kdFov4U8VbopBg=","attestation":{"credentialId":"VlcKd9AVLXjcG6MCEffnNg==","clientDataJson":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiX3VPc0JJTGNGY05EZ3NreW5VenpYLWxTSWlpVjFrZEZvdjRVOFZib3BCZyIsIm9yaWdpbiI6Imh0dHBzOi8vcGFzc2tleS1zaWduLm5ldGxpZnkuYXBwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUb8sgDD5/CBX6WLpDxIlLuZ9Bl+AYEiO+pO3vkKtzKwRdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEFZXCnfQFS143BujAhH35zalAQIDJiABIVggu2xCTI5eULKsMmA0COAQW11+5gKoFSE5Hb8WMVgsVE4iWCDypFrFRL7gmrgAZK/rqYw0XvX3VmfTVrGjt3faAXbKHA==","transports":["AUTHENTICATOR_TRANSPORT_INTERNAL"]}}]}}';
const examplePrivateKey =
  "9b7d22a02a7eea4304c8d67598a5f7ae0c9e0940a9f7a0da996f52ccf294b56e";
const examplePublicKey =
  "0234f0a564da5785a8b1e72ee70654158092dec0e40dd5e8c390e2b4e217b5ffae";
generateApiKeySignatureWithLogs(
  examplePayload,
  examplePrivateKey,
  examplePublicKey
);
