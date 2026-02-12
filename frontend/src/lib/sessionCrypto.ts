import nacl from "tweetnacl";
import { ethers } from "ethers";

const NONCE_LENGTH = nacl.box.nonceLength;
const PUBLIC_KEY_LENGTH = nacl.box.publicKeyLength;

export type SessionKeyPairHex = {
  publicKeyHex: string;
  secretKeyHex: string;
};

export function generateSessionKeyPairHex(): SessionKeyPairHex {
  const keyPair = nacl.box.keyPair();

  return {
    publicKeyHex: ethers.hexlify(keyPair.publicKey),
    secretKeyHex: ethers.hexlify(keyPair.secretKey)
  };
}

export function decryptSessionCiphertextHex(ciphertextHex: string, secretKeyHex: string): string {
  const payload = ethers.getBytes(ciphertextHex);
  const secretKey = ethers.getBytes(secretKeyHex);

  if (secretKey.length !== nacl.box.secretKeyLength) {
    throw new Error(`Invalid session secret key length: ${secretKey.length}`);
  }

  const minLength = NONCE_LENGTH + PUBLIC_KEY_LENGTH + nacl.box.overheadLength;
  if (payload.length < minLength) {
    throw new Error("Invalid ciphertext payload");
  }

  const nonce = payload.slice(0, NONCE_LENGTH);
  const senderPublicKey = payload.slice(NONCE_LENGTH, NONCE_LENGTH + PUBLIC_KEY_LENGTH);
  const boxed = payload.slice(NONCE_LENGTH + PUBLIC_KEY_LENGTH);

  const opened = nacl.box.open(boxed, nonce, senderPublicKey, secretKey);
  if (!opened) {
    throw new Error("Could not decrypt SDK token payload");
  }

  return new TextDecoder().decode(opened);
}
