import * as dotenv from "dotenv";

dotenv.config();

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
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
  defaultLevelName: process.env.DEFAULT_LEVEL_NAME ?? "basic-kyc",
  tokenTtlSeconds: numberEnv("TOKEN_TTL_SECONDS", 600),
  pollIntervalMs: numberEnv("POLL_INTERVAL_MS", 120000),
  attestationExpirationDays: numberEnv("ATTESTATION_EXPIRATION_DAYS", 180),
  flagHuman: BigInt(numberEnv("FLAG_HUMAN", 1)),
  stateFile: process.env.STATE_FILE ?? ".cre-state.json"
};
