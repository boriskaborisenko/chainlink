# CRE_GO (Backup Implementation)

Backup Chainlink-CRE-style workers implemented in Go.

## What is inside

- `cmd/issue-sdk-token` - listens `KycRequested`, gets Sumsub SDK token, encrypts for user key, stores packet onchain.
- `cmd/sync-kyc-status` - polls Sumsub and writes `attest` / `revoke` in `PassRegistry`.

## Setup

1. Copy env:

```bash
cp .env.example .env
```

2. Fill variables (especially `SUMSUB_APP_TOKEN`, `SUMSUB_SECRET_KEY`).

## Run

Single run:

```bash
go run ./cmd/issue-sdk-token
go run ./cmd/sync-kyc-status
```

Loop mode:

```bash
go run ./cmd/issue-sdk-token --loop
go run ./cmd/sync-kyc-status --loop
```

## Notes

- Designed as reserve implementation for the same onchain contracts used by `cre/` (TypeScript version).
- Sumsub API secrets must stay in env/secret manager only.



cd CRE_GO
cp .env.example .env
# заполнить SUMSUB_APP_TOKEN / SUMSUB_SECRET_KEY
go run ./cmd/issue-sdk-token --loop
go run ./cmd/sync-kyc-status --loop