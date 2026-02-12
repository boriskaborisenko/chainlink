# PassStore + Sumsub + Chainlink CRE (No Backend)

Monorepo with three packages:

- `contracts/` - Solidity contracts (registry, broker, demo gated apps).
- `cre/` - Chainlink CRE workflow workers (SDK token issue + KYC sync polling).
- `frontend/` - React app for wallet flow, Sumsub WebSDK launch, and gated actions.

## Architecture

1. User connects wallet in frontend.
2. User grants encryption key (`eth_getEncryptionPublicKey`) and stores it in `KycSessionBroker`.
3. User calls `requestKyc(levelName)`.
4. CRE workflow `IssueSdkToken` catches `KycRequested`, asks Sumsub for SDK token, encrypts token for user key, writes ciphertext onchain.
5. Frontend reads ciphertext, decrypts using `eth_decrypt`, and launches Sumsub WebSDK.
6. CRE workflow `SyncKycStatus` polls Sumsub statuses and updates `PassRegistry` (`attest`/`revoke`).
7. Demo contracts (`AccessPass`, `ClaimDrop`) gate calls via `PassRegistry.verifyUser`.

## Quick Start

1. Install deps:

```bash
npm install
```

2. Start local chain:

```bash
npx hardhat node --config contracts/hardhat.config.ts
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

6. Fill Sumsub settings in `cre/.env`:

- `SUMSUB_APP_TOKEN`
- `SUMSUB_SECRET_KEY`
- optional endpoint overrides if your Sumsub project uses different paths.

7. Start CRE workers (in separate terminals):

```bash
npm run dev:issue-token -w cre
npm run dev:sync-status -w cre
```

8. Start frontend:

```bash
npm run dev -w frontend
```

## How To Use (E2E)

1. Open frontend and click `Connect wallet`.
2. Click `Enable encryption` (saves MetaMask encryption pubkey onchain).
3. Click `Start verification`.
4. Wait for `IssueSdkToken` worker to store ciphertext in broker packet.
5. Frontend decrypts packet with `eth_decrypt` and launches Sumsub WebSDK.
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
- `cre/src/workflows/issue-sdk-token.ts` - Event-driven SDK token issuance.
- `cre/src/workflows/sync-kyc-status.ts` - Cron-style status sync and onchain updates.
- `frontend/src/App.tsx` - Wallet UX + decrypt + WebSDK + demo actions.

## Notes

- No custom backend and no custom DB are used.
- Sumsub secrets stay in CRE secrets/env only.
- Onchain SDK token packets are encrypted; plaintext is only available to wallet owner.
- This repository is MVP-oriented and intentionally keeps PII offchain/onchain storage minimal.
- In this sandbox, Hardhat may fail downloading remote solc binaries. Solidity source is still checked via local `solcjs`.
