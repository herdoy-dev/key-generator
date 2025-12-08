import crypto from "crypto";

// payload from Step 1
const payloadToSign =
  '{"type":"ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2","organizationId":"b45ddbce-ff77-4f85-b856-f4e28938b51a","timestampMs":"1765211790571","parameters":{"userId":"a77b66bc-0610-4f68-a895-6ec556aee48d","authenticators":[{"authenticatorName":"Platform Authenticator","challenge":"&#x2F;uOsBILcFcNDgskynUzzX+lSIiiV1kdFov4U8VbopBg=","attestation":{"credentialId":"VlcKd9AVLXjcG6MCEffnNg==","clientDataJson":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiX3VPc0JJTGNGY05EZ3NreW5VenpYLWxTSWlpVjFrZEZvdjRVOFZib3BCZyIsIm9yaWdpbiI6Imh0dHBzOi8vcGFzc2tleS1zaWduLm5ldGxpZnkuYXBwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUb8sgDD5/CBX6WLpDxIlLuZ9Bl+AYEiO+pO3vkKtzKwRdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEFZXCnfQFS143BujAhH35zalAQIDJiABIVggu2xCTI5eULKsMmA0COAQW11+5gKoFSE5Hb8WMVgsVE4iWCDypFrFRL7gmrgAZK/rqYw0XvX3VmfTVrGjt3faAXbKHA==","transports":["hybrid","internal"]}}]}}';

// your private key (must match public key registered during API Key setup)
const privateKeyHex =
  "5a5a115886ed38c079086c1526892bd69c8c8a7c110870b5d6463481cd1a4f3c";

// convert payload to bytes
const payloadBuffer = Buffer.from(payloadToSign, "utf8");

// sign using ECDSA with secp256k1 (example)
const sign = crypto.createSign("SHA256");
sign.update(payloadBuffer);
sign.end();

const privateKey = Buffer.from(privateKeyHex, "hex");
const signature = sign
  .sign({
    key: privateKey,
    format: "der",
    type: "sec1",
  })
  .toString("base64");

console.log({
  payloadId: "auth_72a60b0f_48d9_484e_8202_fa952fc104f8",
  signature,
});
