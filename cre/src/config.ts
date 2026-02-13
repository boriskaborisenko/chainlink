import * as dotenv from "dotenv";

dotenv.config();

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }

  if (value === "..." || value.startsWith("PUT_YOUR_")) {
    throw new Error(`Env var ${name} still contains a placeholder value`);
  }

  return value;
}

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Invalid numeric env var ${name}: ${raw}`);
  }

  return parsed;
}

type SumsubUserIdMode = "wallet" | "wallet_request";

function sumsubUserIdModeEnv(name: string, fallback: SumsubUserIdMode): SumsubUserIdMode {
  const raw = process.env[name]?.trim().toLowerCase();
  if (!raw) {
    return fallback;
  }

  if (raw === "wallet" || raw === "wallet_request") {
    return raw;
  }

  throw new Error(`Invalid ${name}: ${raw}. Allowed values: wallet, wallet_request`);
}

export const config = {
  rpcUrl: requireEnv("RPC_URL"),
  creSignerPk: requireEnv("CRE_SIGNER_PK"),
  brokerAddress: requireEnv("KYC_BROKER_ADDRESS"),
  registryAddress: requireEnv("PASS_REGISTRY_ADDRESS"),
  sumsubBaseUrl: process.env.SUMSUB_BASE_URL ?? "https://api.sumsub.com",
  sumsubAppToken: requireEnv("SUMSUB_APP_TOKEN"),
  sumsubSecretKey: requireEnv("SUMSUB_SECRET_KEY"),
  sumsubSdkTokenPath: process.env.SUMSUB_SDK_TOKEN_PATH ?? "/resources/accessTokens/sdk",
  sumsubStatusPathTemplate:
    process.env.SUMSUB_STATUS_PATH_TEMPLATE ?? "/resources/applicants/-;externalUserId={userId}/one",
  // "wallet_request" avoids immediate "already approved" in sandbox by using a fresh externalUserId per request.
  sumsubUserIdMode: sumsubUserIdModeEnv("SUMSUB_USER_ID_MODE", "wallet_request"),
  defaultLevelName: process.env.KYC_LEVEL_NAME ?? process.env.DEFAULT_LEVEL_NAME ?? "basic-kyc",
  tokenTtlSeconds: numberEnv("TOKEN_TTL_SECONDS", 600),
  // Fast loop for onchain KycRequested -> SDK packet delivery.
  // Keep POLL_INTERVAL_MS name for backward compatibility.
  pollIntervalMs: numberEnv("POLL_INTERVAL_MS", 5000),
  // Slower Sumsub status sync cadence to avoid excessive provider/API calls.
  syncPollIntervalMs: numberEnv("SYNC_POLL_INTERVAL_MS", 120000),
  attestationExpirationDays: numberEnv("ATTESTATION_EXPIRATION_DAYS", 180),
  flagHuman: BigInt(numberEnv("FLAG_HUMAN", 1)),
  stateFile: process.env.STATE_FILE ?? ".cre-state.json"
};
