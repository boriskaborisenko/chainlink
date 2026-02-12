import { EventLog, ethers } from "ethers";
import { getBroker, getProvider, getRegistry } from "../clients/chain.js";
import { getReviewStatusByUserId } from "../clients/sumsub.js";
import { config } from "../config.js";
import { readState, writeState } from "../state.js";
import { KycRequestEventData, ReviewDecision } from "../types.js";
import { shouldLoop, sleep } from "./shared.js";

async function readKycRequests(fromBlock: number, toBlock: number): Promise<KycRequestEventData[]> {
  if (fromBlock > toBlock) {
    return [];
  }

  const broker = getBroker();
  const filter = broker.filters.KycRequested();
  const logs = await broker.queryFilter(filter, fromBlock, toBlock);

  const eventLogs = logs.filter((log): log is EventLog => "args" in log);

  return eventLogs.map((log) => ({
    requestId: log.args?.requestId as bigint,
    user: log.args?.user as string,
    levelName: (log.args?.levelName as string) || config.defaultLevelName,
    blockNumber: log.blockNumber
  }));
}

async function upsertAttestation(user: string): Promise<void> {
  const registry = getRegistry();
  const expiration = BigInt(Math.floor(Date.now() / 1000) + config.attestationExpirationDays * 24 * 60 * 60);
  const refHash = ethers.keccak256(ethers.toUtf8Bytes(`${user}:${Date.now()}`));

  const tx = await registry.attest(user, {
    flags: config.flagHuman,
    expiration,
    riskScore: 0,
    subjectType: 1,
    refHash
  });

  await tx.wait();
  console.log(`attested user=${user}`);
}

async function revokeAttestation(user: string): Promise<void> {
  const registry = getRegistry();
  const current = await registry.attestations(user);
  const exists = Boolean(current[7]);

  if (!exists) {
    console.log(`user=${user} has no attestation yet; skip revoke`);
    return;
  }

  const tx = await registry.revoke(user);
  await tx.wait();
  console.log(`revoked user=${user}`);
}

async function applyDecision(user: string, decision: ReviewDecision): Promise<void> {
  if (decision === "GREEN") {
    await upsertAttestation(user);
    return;
  }

  if (decision === "RED") {
    await revokeAttestation(user);
    return;
  }

  console.log(`user=${user} still pending`);
}

async function runOnce(): Promise<void> {
  const provider = getProvider();
  const latest = await provider.getBlockNumber();
  const state = readState();

  const fromBlock = state.lastSyncBlock > 0 ? state.lastSyncBlock + 1 : Math.max(0, latest - 2000);
  const recentRequests = await readKycRequests(fromBlock, latest);

  for (const event of recentRequests) {
    const key = event.user.toLowerCase();
    state.users[key] = {
      ...state.users[key],
      userId: event.user,
      lastSeenRequestId: event.requestId.toString()
    };
  }

  const users = Object.entries(state.users);
  if (users.length === 0) {
    console.log("SyncKycStatus: no users to check yet");
  }

  for (const [key, userState] of users) {
    const user = userState.userId ?? key;

    try {
      const status = await getReviewStatusByUserId(user);
      const previous = state.users[key]?.lastReviewDecision;

      if (status.decision !== previous) {
        await applyDecision(user, status.decision);
      } else {
        console.log(`user=${user} status unchanged (${status.decision})`);
      }

      state.users[key] = {
        ...state.users[key],
        userId: user,
        lastReviewDecision: status.decision,
        lastSyncAt: new Date().toISOString()
      };
    } catch (err) {
      console.error(`failed to sync user=${user}:`, err);
    }
  }

  state.lastSyncBlock = latest;
  writeState(state);
}

async function main() {
  if (!shouldLoop()) {
    await runOnce();
    return;
  }

  console.log(`SyncKycStatus worker started with interval=${config.pollIntervalMs}ms`);
  while (true) {
    try {
      await runOnce();
    } catch (err) {
      console.error("SyncKycStatus loop error:", err);
    }

    await sleep(config.pollIntervalMs);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
