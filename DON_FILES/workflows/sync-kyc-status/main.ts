/**
 * DON template: SyncKycStatus workflow
 *
 * Trigger:
 * - Cron (e.g. every 2 minutes)
 *
 * Steps inside callback:
 * 1. Resolve users to check (from recent KycRequested events or dedicated onchain queue)
 * 2. Read SUMSUB secrets from DON Vault
 * 3. Query Sumsub review status per user
 * 4. Write PassRegistry.attest(...) on GREEN
 * 5. Write PassRegistry.revoke(...) on RED
 * 6. Ignore/keep pending on PENDING + treat 404 Applicant not found as PENDING
 *
 * NOTE:
 * This file is intentionally TODO-style to keep it compatible with your current repo
 * while you wire exact CRE SDK calls from `cre init` scaffolding.
 */

export async function main(): Promise<void> {
  throw new Error(
    "TODO: Implement DON cron handler using CRE SDK scaffold (create with `cre init workflow typescript` and port local logic)."
  );
}
