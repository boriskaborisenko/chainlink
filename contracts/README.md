# Contracts Package

Contains MVP smart contracts for no-backend PassStore architecture.

## Contracts

- `PassRegistry.sol` - attestations, issuer allowlist, policies, and `verifyUser`.
- `KycSessionBroker.sol` - stores encryption keys, KYC requests, and encrypted SDK token packets.
- `AccessPass.sol` - demo mint gated by `verifyUser`.
- `ClaimDrop.sol` - demo claim gated by `verifyUser`.

## Usage

1. Copy `.env.example` to `.env`.
2. Start local node (`npx hardhat node`) or configure Sepolia RPC.
3. Compile/deploy:

```bash
npm run compile
npm run deploy:local
```

If Hardhat cannot download the compiler in restricted environments, run:

```bash
npm run check:solcjs
```

## Key Events

- `PassRegistry.Attested`, `PassRegistry.Revoked`
- `KycSessionBroker.KycRequested`, `KycSessionBroker.TokenStored`
