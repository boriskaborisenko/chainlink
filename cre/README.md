# CRE Workflows Package

This package acts as the no-backend server role for Sumsub integration.

## Workflows

- `UnifiedWorker` (`src/workflows/worker.ts`)
  - Pass A: watches `KycSessionBroker.KycRequested`, creates Sumsub SDK token, encrypts it for user session key, stores ciphertext onchain.
  - Pass B: polls Sumsub review status for known users and updates `PassRegistry`:
    - `GREEN` -> `attest(...)`
    - `RED` -> `revoke(...)`
    - `PENDING` -> no write

## Run

1. Copy `.env.example` to `.env` and fill contract addresses + Sumsub credentials.
   - `POLL_INTERVAL_MS` controls how fast `KycRequested` events are picked up (recommended `5000` for local demo).
   - `SYNC_POLL_INTERVAL_MS` controls how often Sumsub statuses are synced (recommended `30000-120000`).
2. Start single worker:

```bash
npm run dev:worker
```

## Security Notes

- Sumsub secrets are only read from env (map to CRE/DON secret vault in production).
- SDK token ciphertext is stored onchain; plaintext is not.
- No PII is persisted in local state.
- KYC level name for SDK token issuance is controlled via ENV `KYC_LEVEL_NAME`.
