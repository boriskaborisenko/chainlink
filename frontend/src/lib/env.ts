function requireEnv(name: string): string {
  const value = import.meta.env[name];
  if (!value) {
    throw new Error(`Missing ${name} in frontend env`);
  }
  return value;
}

function parseNumber(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export const env = {
  chainId: parseNumber(import.meta.env.VITE_CHAIN_ID ?? "0", 0),
  policyId: BigInt(parseNumber(import.meta.env.VITE_POLICY_ID ?? "0", 0)),
  kycLevelName: (import.meta.env.VITE_KYC_LEVEL_NAME as string | undefined) ?? "basic-kyc",
  passRegistry: requireEnv("VITE_PASS_REGISTRY"),
  kycBroker: requireEnv("VITE_KYC_BROKER"),
  accessPass: requireEnv("VITE_ACCESS_PASS"),
  claimDrop: requireEnv("VITE_CLAIM_DROP"),
  creIssuer: import.meta.env.VITE_CRE_ISSUER as string | undefined
};
