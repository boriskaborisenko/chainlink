# CRE Workflows Package

This package acts as the no-backend server role for Sumsub integration.

## Workflows

- `IssueSdkToken` (`src/workflows/issue-sdk-token.ts`)
  - Watches `KycSessionBroker.KycRequested`.
  - Calls Sumsub to generate an SDK token.
  - Encrypts token for the user's MetaMask encryption key.
  - Stores ciphertext onchain via `storeEncryptedToken`.

- `SyncKycStatus` (`src/workflows/sync-kyc-status.ts`)
  - Polls Sumsub review status for known users.
  - `GREEN` -> `PassRegistry.attest(...)`
  - `RED` -> `PassRegistry.revoke(...)`
  - `PENDING` -> no onchain write.

## Run

1. Copy `.env.example` to `.env` and fill contract addresses + Sumsub credentials.
2. Start workers in separate terminals:

```bash
npm run dev:issue-token
npm run dev:sync-status
```

## Security Notes

- Sumsub secrets are only read from env (map to CRE/DON secret vault in production).
- SDK token ciphertext is stored onchain; plaintext is not.
- No PII is persisted in local state.

