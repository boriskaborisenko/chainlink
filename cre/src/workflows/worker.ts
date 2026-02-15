import { EventLog, ethers } from "ethers";
import { BROKER_ABI } from "../abi.js";
import { getBroker, getProvider, getRegistry } from "../clients/chain.js";
import { encryptForSessionKey } from "../clients/crypto.js";
import { generateSdkToken, getReviewStatusByUserId } from "../clients/sumsub.js";
import { config } from "../config.js";
import { readState, writeState } from "../state.js";
import {
  KycRequestEventData,
  KycSyncRequestEventData,
  ReviewDecision,
  WorkflowState,
  WorldIdVerificationRequestEventData
} from "../types.js";
import { attestWorldIdFlag, WorldIdProof } from "../worldid/verify.js";
import { shouldLoop, sleep } from "./shared.js";

const LOG_LOOKBACK_BLOCKS = 2000;
const BROKER_IFACE = new ethers.Interface(BROKER_ABI);

function requestStateKey(user: string, requestId: bigint): string {
  return `${user.toLowerCase()}:${requestId.toString()}`;
}

function fallbackSumsubUserId(user: string, requestId: bigint): string {
  const normalizedUser = user.toLowerCase();

  if (config.sumsubUserIdMode === "wallet_request") {
    return `${normalizedUser}_${requestId.toString()}`;
  }

  return normalizedUser;
}

function resolveSumsubUserIdForIssue(state: WorkflowState, user: string, requestId: bigint): string {
  if (config.sumsubUserIdMode === "wallet") {
    const value = user.toLowerCase();
    state.sumsubUserIds[requestStateKey(user, requestId)] = value;
    return value;
  }

  const uniqueSuffix = Date.now().toString(36);
  const value = `${user.toLowerCase()}_${requestId.toString()}_${uniqueSuffix}`;
  state.sumsubUserIds[requestStateKey(user, requestId)] = value;
  return value;
}

function resolveSumsubUserIdForSync(state: WorkflowState, user: string, requestId: bigint): string {
  const mapped = state.sumsubUserIds[requestStateKey(user, requestId)];
  if (mapped) {
    return mapped;
  }

  const fallback = fallbackSumsubUserId(user, requestId);
  console.warn(
    `missing sumsubUserId mapping for user=${user} requestId=${requestId.toString()}, falling back to ${fallback}`
  );
  return fallback;
}

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

async function readKycSyncRequests(fromBlock: number, toBlock: number): Promise<KycSyncRequestEventData[]> {
  if (fromBlock > toBlock) {
    return [];
  }

  const broker = getBroker();
  const filter = broker.filters.KycSyncRequested();
  const logs = await broker.queryFilter(filter, fromBlock, toBlock);

  const eventLogs = logs.filter((log): log is EventLog => "args" in log);

  return eventLogs.map((log) => ({
    syncRequestId: log.args?.syncRequestId as bigint,
    user: log.args?.user as string,
    requestId: log.args?.requestId as bigint,
    blockNumber: log.blockNumber
  }));
}

async function readWorldIdRequests(fromBlock: number, toBlock: number): Promise<WorldIdVerificationRequestEventData[]> {
  if (fromBlock > toBlock) {
    return [];
  }

  const broker = getBroker();
  const filter = broker.filters.WorldIdVerificationRequested();
  const logs = await broker.queryFilter(filter, fromBlock, toBlock);
  const eventLogs = logs.filter((log): log is EventLog => "args" in log);

  return eventLogs.map((log) => ({
    worldIdRequestId: log.args?.worldIdRequestId as bigint,
    user: log.args?.user as string,
    nullifierHash: (log.args?.nullifierHash as string) || "",
    verificationLevel: (log.args?.verificationLevel as string) || "",
    txHash: log.transactionHash,
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

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Missing or invalid ${label} in requestWorldIdVerification calldata`);
  }
  return value;
}

async function decodeWorldIdProofFromTx(txHash: string): Promise<WorldIdProof> {
  const provider = getProvider();
  const tx = await provider.getTransaction(txHash);
  if (!tx) {
    throw new Error(`World ID tx not found: ${txHash}`);
  }

  const parsed = BROKER_IFACE.parseTransaction({
    data: tx.data,
    value: tx.value
  });

  if (!parsed || parsed.name !== "requestWorldIdVerification") {
    throw new Error(`Unexpected tx payload for World ID request: ${txHash}`);
  }

  const proof = requireNonEmptyString(parsed.args.proof, "proof");
  const merkleRoot = requireNonEmptyString(parsed.args.merkleRoot, "merkleRoot");
  const nullifierHash = requireNonEmptyString(parsed.args.nullifierHash, "nullifierHash");
  const verificationLevel = requireNonEmptyString(parsed.args.verificationLevel, "verificationLevel");

  return {
    proof,
    merkle_root: merkleRoot,
    nullifier_hash: nullifierHash,
    verification_level: verificationLevel
  };
}

async function processIssueEvent(event: KycRequestEventData, state: WorkflowState): Promise<void> {
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

  const sumsubUserId = resolveSumsubUserIdForIssue(state, event.user, event.requestId);
  console.log(
    `issuing sdk token requestId=${event.requestId.toString()} user=${event.user} sumsubUserId=${sumsubUserId} mode=${config.sumsubUserIdMode}`
  );
  const tokenResponse = await generateSdkToken(sumsubUserId, configuredLevel, config.tokenTtlSeconds);

  const ciphertext = encryptForSessionKey(userPubKey, tokenResponse.token);
  const expiresAt = BigInt(Math.floor(Date.now() / 1000) + config.tokenTtlSeconds);

  const tx = await broker.storeEncryptedToken(event.requestId, ethers.hexlify(ciphertext), expiresAt);
  await tx.wait();

  console.log(
    `stored encrypted token for requestId=${event.requestId.toString()} user=${event.user} sumsubUserId=${sumsubUserId}`
  );
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

  for (const event of events) {
    try {
      await processIssueEvent(event, state);
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
  const current = await registry.attestations(user);
  const currentFlags = BigInt(current[0]);
  const currentExpiration = Number(current[1]);
  const currentRevoked = Boolean(current[6]);
  const currentExists = Boolean(current[7]);
  const nextFlags = currentFlags | config.flagHuman;
  const now = Math.floor(Date.now() / 1000);

  // Idempotent fast-path: if a valid non-revoked HUMAN attestation already exists,
  // avoid extra txs on repeated sync requests.
  if (
    currentExists &&
    !currentRevoked &&
    (currentFlags & config.flagHuman) === config.flagHuman &&
    currentExpiration > now
  ) {
    console.log(`user=${user} already has active HUMAN attestation, skip`);
    return;
  }

  const expiration = BigInt(now + config.attestationExpirationDays * 24 * 60 * 60);
  const refHash = ethers.keccak256(ethers.toUtf8Bytes(`${user}:${Date.now()}`));

  const tx = await registry.attest(user, {
    flags: nextFlags,
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

async function runSyncKycStatusPass(latestBlock: number): Promise<void> {
  const state = readState();
  const fromBlock = resolveFromBlock(state.lastSyncBlock, latestBlock, "SyncKycStatus");

  if (fromBlock > latestBlock) {
    state.lastSyncBlock = latestBlock;
    writeState(state);
    return;
  }

  const syncEvents = await readKycSyncRequests(fromBlock, latestBlock);
  if (syncEvents.length === 0) {
    state.lastSyncBlock = latestBlock;
    writeState(state);
    return;
  }

  const latestSyncRequestByUser = new Map<string, KycSyncRequestEventData>();
  for (const event of syncEvents) {
    const key = event.user.toLowerCase();
    latestSyncRequestByUser.set(key, event);

    state.users[key] = {
      ...state.users[key],
      userId: event.user,
      lastSeenRequestId: event.requestId.toString()
    };
  }

  for (const [key, event] of latestSyncRequestByUser.entries()) {
    const user = event.user;
    const sumsubUserId = resolveSumsubUserIdForSync(state, user, event.requestId);

    try {
      const status = await getReviewStatusByUserId(sumsubUserId);
      const previous = state.users[key]?.lastReviewDecision;

      // Re-apply terminal decisions idempotently so redeploys/state resets
      // still restore expected onchain attestation without manual cleanup.
      if (status.decision === "GREEN" || status.decision === "RED") {
        await applyDecision(user, status.decision);
        if (status.decision === previous) {
          console.log(`user=${user} status unchanged (${status.decision}), re-applied onchain check`);
        }
      } else {
        console.log(`user=${user} still pending`);
      }

      state.users[key] = {
        ...state.users[key],
        userId: user,
        lastSeenRequestId: event.requestId.toString(),
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

async function processWorldIdEvent(event: WorldIdVerificationRequestEventData): Promise<void> {
  const proof = await decodeWorldIdProofFromTx(event.txHash);

  if (event.nullifierHash && event.nullifierHash !== proof.nullifier_hash) {
    throw new Error(
      `Nullifier mismatch for worldIdRequestId=${event.worldIdRequestId.toString()} event=${event.nullifierHash} tx=${proof.nullifier_hash}`
    );
  }

  const result = await attestWorldIdFlag(event.user, proof);
  if (result.alreadyVerified) {
    console.log(`worldId requestId=${event.worldIdRequestId.toString()} user=${event.user} already has world-id flag`);
    return;
  }

  console.log(
    `worldId verified requestId=${event.worldIdRequestId.toString()} user=${event.user} tx=${result.txHash ?? "n/a"}`
  );
}

async function runWorldIdPass(latestBlock: number): Promise<void> {
  if (!config.worldIdAppId || !config.worldIdAction) {
    return;
  }

  const state = readState();
  const fromBlock = resolveFromBlock(state.lastWorldIdBlock, latestBlock, "WorldIdVerify");

  if (fromBlock > latestBlock) {
    state.lastWorldIdBlock = latestBlock;
    writeState(state);
    return;
  }

  const events = await readWorldIdRequests(fromBlock, latestBlock);

  for (const event of events) {
    try {
      await processWorldIdEvent(event);
    } catch (err) {
      console.error(
        `WorldId verification failed worldIdRequestId=${event.worldIdRequestId.toString()} user=${event.user} tx=${event.txHash}`,
        err
      );
    }
  }

  state.lastWorldIdBlock = latestBlock;
  writeState(state);
}

async function runOnce(): Promise<void> {
  const provider = getProvider();
  const latest = await provider.getBlockNumber();

  await runIssueSdkTokenPass(latest);
  await runSyncKycStatusPass(latest);
  await runWorldIdPass(latest);
}

async function main() {
  if (!shouldLoop()) {
    await runOnce();
    return;
  }

  console.log(
    `Unified CRE worker started with loopInterval=${config.pollIntervalMs}ms (KYC sync + World ID are event-driven)`
  );

  while (true) {
    const loopStartedAt = Date.now();
    try {
      const provider = getProvider();
      const latest = await provider.getBlockNumber();

      await runIssueSdkTokenPass(latest);
      await runSyncKycStatusPass(latest);
      await runWorldIdPass(latest);
    } catch (err) {
      console.error("Unified CRE loop error:", err);
    }

    const elapsedMs = Date.now() - loopStartedAt;
    const sleepMs = Math.max(0, config.pollIntervalMs - elapsedMs);
    await sleep(sleepMs);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
