import { EventLog, ethers } from "ethers";
import { getBroker, getProvider, getRegistry } from "../clients/chain.js";
import { encryptForSessionKey } from "../clients/crypto.js";
import { generateSdkToken, getReviewStatusByUserId } from "../clients/sumsub.js";
import { config } from "../config.js";
import { readState, writeState } from "../state.js";
import { KycRequestEventData, ReviewDecision } from "../types.js";
import { shouldLoop, sleep } from "./shared.js";

const LOG_LOOKBACK_BLOCKS = 2000;

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

function resolveFromBlock(lastProcessedBlock: number, latestBlock: number, scope: string): number {
  if (lastProcessedBlock <= 0) {
    return Math.max(0, latestBlock - LOG_LOOKBACK_BLOCKS);
  }

  if (lastProcessedBlock > latestBlock) {
    console.warn(
      `${scope}: chain rewind detected (lastProcessed=${lastProcessedBlock}, latest=${latestBlock}), resetting cursor`
    );
    return Math.max(0, latestBlock - LOG_LOOKBACK_BLOCKS);
  }

  return lastProcessedBlock + 1;
}

async function processIssueEvent(event: KycRequestEventData): Promise<void> {
  const broker = getBroker();

  const packet = await broker.getPacket(event.requestId);
  const ciphertextHex = packet[1] as string;

  if (ciphertextHex !== "0x") {
    console.log(`requestId=${event.requestId.toString()} already has token packet, skipping`);
    return;
  }

  const pubKeyBytes = (await broker.encryptionPubKey(event.user)) as string;
  if (pubKeyBytes === "0x") {
    console.log(`user=${event.user} has no encryption key, skipping requestId=${event.requestId.toString()}`);
    return;
  }

  const userPubKey = ethers.getBytes(pubKeyBytes);
  if (userPubKey.length !== 32) {
    console.log(
      `user=${event.user} has invalid encryption key length=${userPubKey.length}, skipping requestId=${event.requestId.toString()}`
    );
    return;
  }

  const configuredLevel = config.defaultLevelName;
  if (event.levelName && event.levelName !== configuredLevel) {
    console.log(
      `requestId=${event.requestId.toString()} event level '${event.levelName}' overridden by ENV level '${configuredLevel}'`
    );
  }

  const tokenResponse = await generateSdkToken(event.user, configuredLevel, config.tokenTtlSeconds);

  const ciphertext = encryptForSessionKey(userPubKey, tokenResponse.token);
  const expiresAt = BigInt(Math.floor(Date.now() / 1000) + config.tokenTtlSeconds);

  const tx = await broker.storeEncryptedToken(event.requestId, ethers.hexlify(ciphertext), expiresAt);
  await tx.wait();

  console.log(`stored encrypted token for requestId=${event.requestId.toString()} user=${event.user}`);
}

async function runIssueSdkTokenPass(latestBlock: number): Promise<void> {
  const state = readState();
  const fromBlock = resolveFromBlock(state.lastIssueTokenBlock, latestBlock, "IssueSdkToken");

  if (fromBlock > latestBlock) {
    state.lastIssueTokenBlock = latestBlock;
    writeState(state);
    return;
  }

  const events = await readKycRequests(fromBlock, latestBlock);

  if (events.length === 0) {
    console.log(`IssueSdkToken: no KycRequested events in blocks ${fromBlock}-${latestBlock}`);
  }

  for (const event of events) {
    try {
      await processIssueEvent(event);
    } catch (err) {
      console.error(`IssueSdkToken event failed requestId=${event.requestId.toString()} user=${event.user}`, err);
    }

    const key = event.user.toLowerCase();
    state.users[key] = {
      ...state.users[key],
      userId: event.user,
      lastSeenRequestId: event.requestId.toString()
    };
  }

  state.lastIssueTokenBlock = latestBlock;
  writeState(state);
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

async function isRequestConsumed(requestId: string): Promise<boolean> {
  const broker = getBroker();
  const packet = await broker.getPacket(BigInt(requestId));

  const ciphertextHex = packet[1] as string;
  const consumed = Boolean(packet[3]);
  const exists = Boolean(packet[4]);

  if (!exists || ciphertextHex === "0x") {
    return false;
  }

  return consumed;
}

async function runSyncKycStatusPass(latestBlock: number): Promise<void> {
  const state = readState();
  const fromBlock = resolveFromBlock(state.lastSyncBlock, latestBlock, "SyncKycStatus");

  if (fromBlock <= latestBlock) {
    const recentRequests = await readKycRequests(fromBlock, latestBlock);

    for (const event of recentRequests) {
      const key = event.user.toLowerCase();
      state.users[key] = {
        ...state.users[key],
        userId: event.user,
        lastSeenRequestId: event.requestId.toString()
      };
    }
  }

  const users = Object.entries(state.users);
  if (users.length === 0) {
    console.log("SyncKycStatus: no users to check yet");
  }

  for (const [key, userState] of users) {
    const user = userState.userId ?? key;
    const lastSeenRequestId = userState.lastSeenRequestId;

    try {
      if (lastSeenRequestId) {
        const consumed = await isRequestConsumed(lastSeenRequestId);

        // Do not block status sync forever on unconsumed requestIds.
        // This can happen when user starts multiple requests and only completes an older one.
        if (!consumed) {
          const previous = state.users[key]?.lastReviewDecision;
          if (previous && previous !== "PENDING") {
            state.users[key] = {
              ...state.users[key],
              userId: user,
              lastReviewDecision: "PENDING",
              lastSyncAt: new Date().toISOString()
            };
          }
        }
      }

      const status = await getReviewStatusByUserId(user);
      const previous = state.users[key]?.lastReviewDecision;

      if (status.decision !== previous) {
        await applyDecision(user, status.decision);
      } else if (status.decision !== "PENDING") {
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

  state.lastSyncBlock = latestBlock;
  writeState(state);
}

async function runOnce(): Promise<void> {
  const provider = getProvider();
  const latest = await provider.getBlockNumber();

  await runIssueSdkTokenPass(latest);
  await runSyncKycStatusPass(latest);
}

async function main() {
  if (!shouldLoop()) {
    await runOnce();
    return;
  }

  console.log(`Unified CRE worker started with interval=${config.pollIntervalMs}ms`);
  while (true) {
    try {
      await runOnce();
    } catch (err) {
      console.error("Unified CRE loop error:", err);
    }

    await sleep(config.pollIntervalMs);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
