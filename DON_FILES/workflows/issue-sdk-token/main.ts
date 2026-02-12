/**
 * DON template: IssueSdkToken workflow
 *
 * Trigger:
 * - EVM log: KycRequested(requestId, user, levelName) from KycSessionBroker
 *
 * Steps inside callback:
 * 1. Read encryptionPubKey(user) from broker
 * 2. Read SUMSUB_APP_TOKEN + SUMSUB_SECRET_KEY from DON secrets
 * 3. Call Sumsub Generate SDK token
 * 4. Encrypt SDK token for session pubkey (nonce+ephemeralPub+ciphertext)
 * 5. Write broker.storeEncryptedToken(requestId, ciphertext, expiresAt)
 *
 * NOTE:
 * This file is intentionally TODO-style to keep it compatible with your current repo
 * while you wire exact CRE SDK calls from `cre init` scaffolding.
 */

export async function main(): Promise<void> {
  throw new Error(
    "TODO: Implement DON handler using CRE SDK scaffold (create with `cre init workflow typescript` and port local logic)."
  );
}
