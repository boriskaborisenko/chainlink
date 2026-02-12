import { EventLog, ethers } from "ethers";
import { getBroker, getProvider } from "../clients/chain.js";
import { encryptForMetaMask } from "../clients/crypto.js";
import { generateSdkToken } from "../clients/sumsub.js";
import { config } from "../config.js";
import { readState, writeState } from "../state.js";
import { KycRequestEventData } from "../types.js";
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

async function processEvent(event: KycRequestEventData): Promise<void> {
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

  const userPubKey = ethers.toUtf8String(pubKeyBytes);
  const tokenResponse = await generateSdkToken(event.user, event.levelName, config.tokenTtlSeconds);

  const ciphertext = encryptForMetaMask(userPubKey, tokenResponse.token);
  const expiresAt = BigInt(Math.floor(Date.now() / 1000) + config.tokenTtlSeconds);

  const tx = await broker.storeEncryptedToken(event.requestId, ethers.hexlify(ciphertext), expiresAt);
  await tx.wait();

  console.log(`stored encrypted token for requestId=${event.requestId.toString()} user=${event.user}`);
}

async function runOnce(): Promise<void> {
  const provider = getProvider();
  const latest = await provider.getBlockNumber();
  const state = readState();

  const fromBlock = state.lastIssueTokenBlock > 0 ? state.lastIssueTokenBlock + 1 : Math.max(0, latest - 2000);
  const events = await readKycRequests(fromBlock, latest);

  if (events.length === 0) {
    console.log(`IssueSdkToken: no KycRequested events in blocks ${fromBlock}-${latest}`);
  }

  for (const event of events) {
    await processEvent(event);
    const key = event.user.toLowerCase();
    state.users[key] = {
      ...state.users[key],
      userId: event.user,
      lastSeenRequestId: event.requestId.toString()
    };
  }

  state.lastIssueTokenBlock = latest;
  writeState(state);
}

async function main() {
  if (!shouldLoop()) {
    await runOnce();
    return;
  }

  console.log(`IssueSdkToken worker started with interval=${config.pollIntervalMs}ms`);
  while (true) {
    try {
      await runOnce();
    } catch (err) {
      console.error("IssueSdkToken loop error:", err);
    }

    await sleep(config.pollIntervalMs);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
