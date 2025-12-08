import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";
import crypto from "crypto";

// Base64URL encode ArrayBuffer
const toBase64UrlBytes = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = Buffer.from(binary, "binary").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const getChallengeFromPayload = async (payload) => {
  const hashBuffer = crypto.createHash("sha256").update(payload).digest();
  const hexString = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return Buffer.from(hexString, "utf-8");
};

export const generateAuthOptionsForPayload = async (
  payload,
  rpId,
  allowCredentials = [],
  timeout = 5 * 60 * 1000,
  userVerification = "preferred"
) => {
  // Get challenge from payload
  const challengeBuffer = await getChallengeFromPayload(payload);
  const challenge = isoBase64URL.fromBuffer(challengeBuffer);

  // Convert allowCredentials from base64url to Buffer
  const allowCredentialsFormatted = allowCredentials.map((cred) => ({
    id: cred,
    type: "public-key",
  }));

  // Generate authentication options
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: allowCredentialsFormatted,
    userVerification,
    timeout,
    challenge,
  });

  return {
    options,
    challenge: Array.from(challengeBuffer)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  };
};

export const verifyAndSignPayload = async (
  payload,
  authenticationResponse,
  rpId,
  expectedChallenge,
  expectedOrigin,
  requireUserVerification = false
) => {
  // Verify the authentication response
  const verification = await verifyAuthenticationResponse({
    response: authenticationResponse,
    expectedChallenge,
    expectedOrigin,
    expectedRPID: rpId,
    requireUserVerification,
  });

  if (!verification.verified) {
    throw new Error("WebAuthn verification failed");
  }

  // Extract data from response
  const { authenticatorData, clientDataJSON, signature } =
    authenticationResponse;

  // Encode all data as base64url
  const authenticatorDataB64 = toBase64UrlBytes(
    isoUint8Array.fromHex(authenticatorData)
  );
  const clientDataJsonB64 = toBase64UrlBytes(
    isoUint8Array.fromHex(clientDataJSON)
  );
  const signatureB64 = toBase64UrlBytes(isoUint8Array.fromHex(signature));
  const credentialIdB64 = authenticationResponse.id;

  // Construct signature object
  const stampObj = {
    authenticatorData: authenticatorDataB64,
    clientDataJson: clientDataJsonB64,
    credentialId: credentialIdB64,
    signature: signatureB64,
  };

  const signatureResult = JSON.stringify(stampObj);

  return {
    signature: signatureResult,
    details: {
      challenge: Array.from(Buffer.from(expectedChallenge, "base64url"))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
      credentialId: credentialIdB64,
      rpId,
      verification,
    },
  };
};

export const signPayloadWithPasskey = async (
  payload,
  rpId,
  userVerification = "preferred"
) => {
  throw new Error(
    "For Node.js, use generateAuthOptionsForPayload and verifyAndSignPayload separately. " +
      "WebAuthn requires client-side interaction which Node.js alone cannot provide."
  );
};

// Helper function to convert base64url to Buffer
export const base64UrlToBuffer = (base64Url) => {
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  const paddedBase64 = pad ? base64 + "=".repeat(4 - pad) : base64;
  return Buffer.from(paddedBase64, "base64");
};

// Helper function to convert Buffer to base64url
export const bufferToBase64Url = (buffer) => {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};
