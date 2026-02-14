# DON_FILES/GO (Backup Implementation)

Backup Chainlink-CRE-style workers implemented in Go.

## What is inside

- `cmd/worker` - unified worker:
  - pass `IssueSdkToken`: listens `KycRequested`, gets Sumsub SDK token, encrypts for user session key, stores packet onchain.
  - pass `SyncKycStatus`: polls Sumsub and writes `attest` / `revoke` in `PassRegistry`.

## Setup

1. Copy env:

```bash
cp .env.example .env
```

2. Fill variables (especially `SUMSUB_APP_TOKEN`, `SUMSUB_SECRET_KEY`).
   - `POLL_INTERVAL_MS` controls how fast KYC requests are picked up (recommended `5000` locally).
   - `SYNC_POLL_INTERVAL_MS` controls Sumsub status sync cadence (recommended `30000-120000`).

## Run

Single run:

```bash
go run ./cmd/worker
```

Loop mode:

```bash
go run ./cmd/worker --loop
```

## Notes

- Designed as reserve implementation for the same onchain contracts used by `cre/` (TypeScript version).
- Sumsub API secrets must stay in env/secret manager only.
- KYC level name is controlled by ENV `KYC_LEVEL_NAME` (not by UI-provided value).
