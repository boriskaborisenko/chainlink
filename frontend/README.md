# Frontend Package

React + Vite app that drives the full no-backend user flow.

## User flow in UI

1. Connect wallet.
2. Click `Enable encryption` (generates an in-browser session keypair and stores the session public key via `setEncryptionPubKey`).
3. Click `Start verification`:
   - calls `requestKyc(VITE_KYC_LEVEL_NAME)` (fixed level shown as a UI pill)
   - polls `KycSessionBroker.getPacket(requestId)`
   - decrypts ciphertext locally in browser using the session secret key
   - launches Sumsub WebSDK in-page
4. After Sumsub flow, click `Sync + refresh status`:
   - sends `requestKycSync()` onchain
   - waits for CRE to process `KycSyncRequested`
   - refreshes `verifyUser`
5. Track gated actions (`Mint AccessPass`, `Claim Drop`).

## Run

1. Copy `.env.example` to `.env` and fill contract addresses.
2. Optional WalletConnect:
   - set `VITE_WC_PROJECT_ID`
   - set `VITE_RPC_URL` for your target chain
3. Start:

```bash
npm run dev
```
