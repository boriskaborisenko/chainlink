# PassStore + Sumsub + Chainlink CRE (No Backend)

Monorepo with three packages:

- `contracts/` - Solidity contracts (registry, broker, demo gated apps).
- `cre/` - Chainlink CRE unified worker (SDK token issue + KYC sync polling in one loop).
- `CRE_GO/` - Backup Go implementation of CRE workers (same flow as `cre/`).
- `frontend/` - React app for wallet flow, Sumsub WebSDK launch, and gated actions.

The architecture is provider-agnostic: Sumsub is the first integrated KYC provider, but issuer workflows can be extended to other providers without changing the core gating pattern.

## Architecture

1. User connects wallet in frontend.
2. User generates an in-browser session keypair and stores only the session public key in `KycSessionBroker`.
3. User calls `requestKyc(levelName)`.
4. Unified CRE worker pass `IssueSdkToken` catches `KycRequested`, asks Sumsub for SDK token, encrypts token for user key, writes ciphertext onchain.
5. Frontend reads ciphertext, decrypts locally with session secret key, and launches Sumsub WebSDK.
6. The same unified CRE worker then runs pass `SyncKycStatus`, polls Sumsub statuses, and updates `PassRegistry` (`attest`/`revoke`).
7. Demo contracts (`AccessPass`, `ClaimDrop`) gate calls via `PassRegistry.verifyUser`.

## Quick Start

1. Install deps:

```bash
npm install
```

2. Start local chain:

```bash
npm run node:local -w contracts
```

3. Configure env files:

- `contracts/.env.example` -> `contracts/.env`
- `cre/.env.example` -> `cre/.env`
- `frontend/.env.example` -> `frontend/.env`

4. Deploy contracts:

```bash
npm run compile -w contracts
npm run deploy:local -w contracts
```

5. Copy deployed addresses:

- from deploy output into `frontend/.env`:
  - `VITE_PASS_REGISTRY`
  - `VITE_KYC_BROKER`
  - `VITE_ACCESS_PASS`
  - `VITE_CLAIM_DROP`
- from deploy output into `cre/.env`:
  - `PASS_REGISTRY_ADDRESS`
  - `KYC_BROKER_ADDRESS`
- set `CRE_SIGNER_PK` in `cre/.env` and allowlist that address in contracts deploy (`CRE_ISSUER` in `contracts/.env`) or via admin tx.
- set `KYC_LEVEL_NAME` in `cre/.env` to the exact Sumsub level name from your dashboard.

6. Fill Sumsub settings in `cre/.env`:

- `SUMSUB_APP_TOKEN`
- `SUMSUB_SECRET_KEY`
- optional endpoint overrides if your Sumsub project uses different paths.

7. Start CRE worker:

```bash
npm run dev:worker -w cre
```

8. Start frontend:

```bash
npm run dev -w frontend
```

## How To Use (E2E)

1. Open frontend and click `Connect wallet`.
2. Click `Enable encryption` (creates session keypair in browser and saves session public key onchain).
3. Click `Start verification`.
4. Wait for `IssueSdkToken` worker to store ciphertext in broker packet.
5. Frontend decrypts packet locally with session secret key and launches Sumsub WebSDK.
6. In Sumsub Sandbox, simulate review result (`GREEN` or `RED`).
7. Wait for `SyncKycStatus` tick:
   - `GREEN` -> `PassRegistry.attest`
   - `RED` -> `PassRegistry.revoke`
8. Try demo actions:
   - `Mint AccessPass`
   - `Claim Drop`

## Repository Map

- `contracts/contracts/PassRegistry.sol` - Attestations, policies, `verifyUser`.
- `contracts/contracts/KycSessionBroker.sol` - Encryption keys, KYC requests, encrypted packets.
- `contracts/contracts/AccessPass.sol` - Mint-gated demo app.
- `contracts/contracts/ClaimDrop.sol` - Claim-gated demo app.
- `cre/src/workflows/worker.ts` - Unified worker that performs token issuance pass and KYC sync pass.
- `frontend/src/App.tsx` - Wallet UX + session-key decrypt + WebSDK + demo actions.
- `frontend/src/lib/sessionCrypto.ts` - Session keypair generation and local decrypt helpers.

## Notes

- No custom backend and no custom DB are used.
- Sumsub secrets stay in CRE secrets/env only.
- Onchain SDK token packets are encrypted; plaintext is only available to wallet owner.
- This repository is MVP-oriented and intentionally keeps PII offchain/onchain storage minimal.
- In this sandbox, Hardhat may fail downloading remote solc binaries. Solidity source is still checked via local `solcjs`.
