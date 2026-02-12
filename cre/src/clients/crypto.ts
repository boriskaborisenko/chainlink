import { encrypt } from "@metamask/eth-sig-util";

export function encryptForMetaMask(pubKeyBase64: string, plaintext: string): Uint8Array {
  const encrypted = encrypt({
    publicKey: pubKeyBase64,
    data: plaintext,
    version: "x25519-xsalsa20-poly1305"
  });

  return new TextEncoder().encode(JSON.stringify(encrypted));
}
