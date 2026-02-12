import nacl from "tweetnacl";

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}

export function encryptForSessionKey(recipientPublicKey: Uint8Array, plaintext: string): Uint8Array {
  if (recipientPublicKey.length !== nacl.box.publicKeyLength) {
    throw new Error(`Invalid session public key length: ${recipientPublicKey.length}`);
  }

  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const message = new TextEncoder().encode(plaintext);
  const ciphertext = nacl.box(message, nonce, recipientPublicKey, ephemeral.secretKey);

  return concatBytes([nonce, ephemeral.publicKey, ciphertext]);
}
