import elliptic from "elliptic";
import bs58check from "bs58check";
import fs from "fs";

const EC = elliptic.ec;

const uint8ArrayFromHexString = (hex) => {
  const matches = hex.match(/.{1,2}/g);
  return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
};

const uint8ArrayToHexString = (bytes) => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

async function decryptCredentialBundle(bundleStr, ephemeralPrivateKey) {
  const { CipherSuite, KemId, KdfId, AeadId } = await import("hpke-js");

  const bundleBytes = bs58check.decode(bundleStr);

  console.log("Bundle decoded, length:", bundleBytes.length, "bytes");

  if (bundleBytes.length < 33) {
    throw new Error("Bundle too small");
  }

  const compressedEncappedKeyBuf = bundleBytes.slice(0, 33);
  const ciphertextBuf = bundleBytes.slice(33);

  console.log(
    "Encapped key (compressed):",
    compressedEncappedKeyBuf.length,
    "bytes"
  );
  console.log("Ciphertext length:", ciphertextBuf.length, "bytes");

  const ec = new EC("p256");
  const point = ec.curve.decodePoint(Buffer.from(compressedEncappedKeyBuf));
  const encappedKeyHex = point.encode("hex", false);
  const enc = uint8ArrayFromHexString(encappedKeyHex);

  console.log("Encapped key (uncompressed):", enc.length, "bytes");

  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes256Gcm,
  });

  const recipientKeyPair = ec.keyFromPrivate(ephemeralPrivateKey, "hex");
  const receiverPublicKeyHex = recipientKeyPair.getPublic(false, "hex");
  const receiverPublicKey = uint8ArrayFromHexString(receiverPublicKeyHex);

  console.log(
    "Receiver public key (uncompressed):",
    receiverPublicKey.length,
    "bytes"
  );

  const skR = uint8ArrayFromHexString(ephemeralPrivateKey);
  const recipientKey = await suite.kem.importKey("raw", skR, false);

  const aad = new Uint8Array(enc.length + receiverPublicKey.length);
  aad.set(enc, 0);
  aad.set(receiverPublicKey, enc.length);

  console.log("AAD length:", aad.length, "bytes");

  const info = new TextEncoder().encode("turnkey_hpke");

  const recipientCtx = await suite.createRecipientContext({
    recipientKey,
    enc,
    info,
  });

  const plaintext = await recipientCtx.open(ciphertextBuf, aad);

  const ptBytes =
    plaintext instanceof ArrayBuffer ? new Uint8Array(plaintext) : plaintext;

  const privateKeyHex = uint8ArrayToHexString(ptBytes);

  const keyPair = ec.keyFromPrivate(privateKeyHex, "hex");
  const tempPublicKey = keyPair.getPublic(true, "hex");
  const tempPrivateKey = keyPair.getPrivate("hex").padStart(64, "0");

  return { tempPublicKey, tempPrivateKey };
}

async function main() {
  const bundleStr = process.argv[2];

  if (!bundleStr) {
    console.error("Usage: node decrypt_bundle.js <credential_bundle>");
    process.exit(1);
  }

  try {
    const ephemeralPrivateKey = fs
      .readFileSync("ephemeral_private.hex", "utf8")
      .trim();
    console.log("Loaded private key from: ephemeral_private.hex");
    console.log(
      "Private key length:",
      ephemeralPrivateKey.length,
      "hex chars\n"
    );

    const result = await decryptCredentialBundle(
      bundleStr,
      ephemeralPrivateKey
    );

    console.log("\n=== Decryption Successful ===");
    console.log("Session Public Key:", result.tempPublicKey);
    console.log("Session Private Key:", result.tempPrivateKey);

    fs.writeFileSync("session_private_key.hex", result.tempPrivateKey);
    fs.writeFileSync("session_public_key.hex", result.tempPublicKey);

    console.log("\nSaved to: session_private_key.hex, session_public_key.hex");
  } catch (error) {
    console.error("\n❌ Decryption failed:", error.message);
    process.exit(1);
  }
}

main();
