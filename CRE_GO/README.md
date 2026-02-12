# CRE_GO (Backup Implementation)

Backup Chainlink-CRE-style workers implemented in Go.

## What is inside

- `cmd/worker` - unified worker:
  - pass `IssueSdkToken`: listens `KycRequested`, gets Sumsub SDK token, encrypts for user key, stores packet onchain.
  - pass `SyncKycStatus`: polls Sumsub and writes `attest` / `revoke` in `PassRegistry`.

## Setup

1. Copy env:

```bash
cp .env.example .env
```

2. Fill variables (especially `SUMSUB_APP_TOKEN`, `SUMSUB_SECRET_KEY`).

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



cd CRE_GO
cp .env.example .env
# заполнить SUMSUB_APP_TOKEN / SUMSUB_SECRET_KEY
go run ./cmd/issue-sdk-token --loop
go run ./cmd/sync-kyc-status --loop
