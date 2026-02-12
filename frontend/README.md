# Frontend Package

React + Vite app that drives the full no-backend user flow.

## User flow in UI

1. Connect wallet.
2. Click `Enable encryption` (calls `eth_getEncryptionPublicKey` + `setEncryptionPubKey`).
3. Click `Start verification`:
   - calls `requestKyc(VITE_KYC_LEVEL_NAME)` (fixed level shown as a UI pill)
   - polls `KycSessionBroker.getPacket(requestId)`
   - decrypts ciphertext using `eth_decrypt`
   - launches Sumsub WebSDK in-page
4. Track registry status and gated actions (`Mint AccessPass`, `Claim Drop`).

## Run

1. Copy `.env.example` to `.env` and fill contract addresses.
2. Start:

```bash
npm run dev
```
