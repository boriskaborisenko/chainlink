import { useEffect, useMemo, useRef, useState } from "react";
import { Contract, BrowserProvider, Interface, ethers } from "ethers";
import { useAppKit, useAppKitAccount, useAppKitProvider } from "@reown/appkit/react";
import { IDKitWidget, IErrorState, ISuccessResult, VerificationLevel } from "@worldcoin/idkit";
import { passRegistryAbi } from "./abi/passRegistry";
import { kycBrokerAbi } from "./abi/kycBroker";
import { accessPassAbi } from "./abi/accessPass";
import { claimDropAbi } from "./abi/claimDrop";
import { env } from "./lib/env";
import { decryptSessionCiphertextHex, generateSessionKeyPairHex } from "./lib/sessionCrypto";

type VerifySnapshot = {
  ok: boolean;
  reason: number;
};

type AttestationSnapshot = {
  exists: boolean;
  revoked: boolean;
  flags: string;
  expiration: number;
  riskScore: number;
  subjectType: number;
};

type PendingDecryptPacket = {
  requestId: string;
  ciphertextHex: string;
  expiresAt: number;
  owner: string;
};

type OnchainSnapshot = {
  verify: VerifySnapshot;
  attestationExists: boolean;
  worldIdVerified: boolean;
  hasOnchainEncryptionKey: boolean;
};

type WalletProviderLike = any;
type SimpleActionKind = "connect" | "kyc" | "status";

type ProgressCopy = {
  title: string;
  message: string;
};

type SimpleResultModal = {
  title: string;
  message: string;
  isError: boolean;
};

type SumsubStatusSnapshot = {
  reviewStatus: string;
  reviewAnswer: string;
};

function getSimpleProgressCopy(
  status: string,
  waitingPacket: boolean,
  refreshingStatus: boolean,
  syncWaiting: boolean
): ProgressCopy {
  if (waitingPacket) {
    return {
      title: "Preparing verification",
      message: "We are securely requesting your KYC session. This usually takes a few seconds."
    };
  }

  if (refreshingStatus || syncWaiting) {
    return {
      title: "Updating your status",
      message: "Checking your latest verification result onchain. Please keep this page open."
    };
  }

  if (status.toLowerCase().includes("wallet")) {
    return {
      title: "Action required",
      message: "Please confirm the request in your wallet to continue."
    };
  }

  return {
    title: "Please wait",
    message: "Processing your request..."
  };
}

function reasonLabel(reason: number): string {
  switch (reason) {
    case 0:
      return "OK";
    case 1:
      return "NO_ATTESTATION";
    case 2:
      return "REVOKED";
    case 3:
      return "EXPIRED";
    case 4:
      return "FLAGS_MISSING";
    case 5:
      return "RISK_TOO_HIGH";
    case 6:
      return "SUBJECT_TYPE_MISMATCH";
    case 7:
      return "POLICY_DISABLED";
    default:
      return `UNKNOWN_${reason}`;
  }
}

function shortAddress(address: string): string {
  if (!address) {
    return "-";
  }

  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function makeContracts(runner: ethers.ContractRunner) {
  return {
    registry: new Contract(env.passRegistry, passRegistryAbi, runner),
    broker: new Contract(env.kycBroker, kycBrokerAbi, runner),
    accessPass: new Contract(env.accessPass, accessPassAbi, runner),
    claimDrop: new Contract(env.claimDrop, claimDropAbi, runner)
  };
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function hashSignalToField(signal: string): string {
  const normalized = signal.trim();
  const hashInput = ethers.isHexString(normalized) ? normalized : ethers.toUtf8Bytes(normalized);
  const fullHash = BigInt(ethers.keccak256(hashInput));
  const shifted = fullHash >> 8n;
  return `0x${shifted.toString(16).padStart(64, "0")}`;
}

function worldIdVerifyEndpoint(appId: string): string {
  return `https://developer.worldcoin.org/api/v2/verify/${appId}`;
}

function parseWorldIdVerifyError(rawBody: string, status: number): string {
  const fallback = `World ID pre-check failed (${status})`;
  const body = rawBody.trim();
  if (!body) {
    return fallback;
  }

  try {
    const parsed = JSON.parse(body) as { detail?: string; code?: string };
    if (parsed.detail?.trim()) {
      return parsed.detail.trim();
    }
    if (parsed.code?.trim()) {
      return parsed.code.trim();
    }
    return fallback;
  } catch {
    return `${fallback}: ${body.slice(0, 200)}`;
  }
}

function parseWorldIdVerificationLevel(raw: string): VerificationLevel {
  const normalized = raw.trim().toLowerCase();
  switch (normalized) {
    case "orb":
      return VerificationLevel.Orb;
    case "document":
      return VerificationLevel.Document;
    case "secure_document":
      return VerificationLevel.SecureDocument;
    case "device":
    default:
      return VerificationLevel.Device;
  }
}

function parseWorldIdPrecheckMode(raw: string): "strict" | "soft" | "off" {
  const normalized = raw.trim().toLowerCase();
  if (normalized === "soft" || normalized === "off") {
    return normalized;
  }
  return "strict";
}

const SESSION_SECRET_STORAGE_PREFIX = "passstore:session-secret:";

function sessionSecretStorageKey(address: string): string {
  return `${SESSION_SECRET_STORAGE_PREFIX}${address.toLowerCase()}`;
}

function readSessionSecret(address: string): string {
  if (typeof window === "undefined" || !address) {
    return "";
  }

  try {
    return window.sessionStorage.getItem(sessionSecretStorageKey(address)) ?? "";
  } catch {
    return "";
  }
}

function writeSessionSecret(address: string, secretKeyHex: string): void {
  if (typeof window === "undefined" || !address || !secretKeyHex) {
    return;
  }

  try {
    window.sessionStorage.setItem(sessionSecretStorageKey(address), secretKeyHex);
  } catch {
    // Keep flow working even if browser storage is unavailable.
  }
}

export default function App() {
  const [account, setAccount] = useState<string>("");
  const [chainId, setChainId] = useState<number>(0);
  const [busy, setBusy] = useState<boolean>(false);
  const [refreshingStatus, setRefreshingStatus] = useState<boolean>(false);
  const [syncWaiting, setSyncWaiting] = useState<boolean>(false);
  const [status, setStatus] = useState<string>("Idle");
  const [error, setError] = useState<string>("");
  const [requestId, setRequestId] = useState<string>("-");
  const [sdkTokenPreview, setSdkTokenPreview] = useState<string>("-");
  const [verify, setVerify] = useState<VerifySnapshot>({ ok: false, reason: 1 });
  const [attestation, setAttestation] = useState<AttestationSnapshot | null>(null);
  const [encryptionReady, setEncryptionReady] = useState<boolean>(false);
  const [hasMinted, setHasMinted] = useState<boolean>(false);
  const [hasClaimed, setHasClaimed] = useState<boolean>(false);
  const [creIssuerAllowed, setCreIssuerAllowed] = useState<boolean | null>(null);
  const [pendingDecrypt, setPendingDecrypt] = useState<PendingDecryptPacket | null>(null);
  const [sessionSecretKeyHex, setSessionSecretKeyHex] = useState<string>("");
  const [waitingPacket, setWaitingPacket] = useState<boolean>(false);
  const [sumsubModalOpen, setSumsubModalOpen] = useState<boolean>(false);
  const [worldIdVerified, setWorldIdVerified] = useState<boolean>(false);
  const [worldIdErrorCode, setWorldIdErrorCode] = useState<string>("");
  const [simpleActionKind, setSimpleActionKind] = useState<SimpleActionKind | null>(null);
  const [simpleResultModal, setSimpleResultModal] = useState<SimpleResultModal | null>(null);
  const { open } = useAppKit();
  const { address: appKitAddress, isConnected: isAppKitConnected } = useAppKitAccount({ namespace: "eip155" });
  const { walletProvider } = useAppKitProvider<WalletProviderLike>("eip155");
  const simpleWasBusyRef = useRef<boolean>(false);
  const sessionSecretKeyRef = useRef<string>("");
  const worldIdPollNonceRef = useRef<number>(0);
  const worldIdPendingAddressRef = useRef<string>("");
  const sumsubAutoSyncInFlightRef = useRef<boolean>(false);
  const sumsubAutoSyncCooldownUntilRef = useRef<number>(0);

  const provider = useMemo(() => {
    if (!walletProvider) {
      return null;
    }

    return new BrowserProvider(walletProvider as any);
  }, [walletProvider]);

  useEffect(() => {
    sessionSecretKeyRef.current = sessionSecretKeyHex;
  }, [sessionSecretKeyHex]);

  useEffect(() => {
    const lightClass = "page-theme-light";
    document.body.classList.add(lightClass);

    return () => {
      document.body.classList.remove(lightClass);
    };
  }, []);

  useEffect(() => {
    if (!appKitAddress || !isAppKitConnected) {
      if (account) {
        worldIdPollNonceRef.current += 1;
        worldIdPendingAddressRef.current = "";
        setAccount("");
        setChainId(0);
        setSessionSecretKeyHex("");
        sessionSecretKeyRef.current = "";
        setPendingDecrypt(null);
        setEncryptionReady(false);
        setSumsubModalOpen(false);
        setWorldIdVerified(false);
        setStatus("Wallet disconnected");
      }

      return;
    }

    if (!account || account.toLowerCase() !== appKitAddress.toLowerCase()) {
      worldIdPollNonceRef.current += 1;
      worldIdPendingAddressRef.current = "";
      const restoredSessionSecret = readSessionSecret(appKitAddress);
      setAccount(appKitAddress);
      setSessionSecretKeyHex(restoredSessionSecret);
      sessionSecretKeyRef.current = restoredSessionSecret;
      setPendingDecrypt(null);
      setEncryptionReady(false);
      setSumsubModalOpen(false);
      setWorldIdVerified(false);
      setStatus("Wallet connected");
      window.setTimeout(() => {
        void refreshOnchainData(appKitAddress);
      }, 0);
    }
  }, [account, appKitAddress, isAppKitConnected, provider]);

  useEffect(() => {
    const inProgress = waitingPacket || refreshingStatus || syncWaiting || (busy && simpleActionKind !== null);
    if (inProgress) {
      simpleWasBusyRef.current = true;
      return;
    }

    if (!simpleWasBusyRef.current || !simpleActionKind) {
      return;
    }

    simpleWasBusyRef.current = false;

    if (error) {
      setSimpleResultModal({
        title: "Action not completed",
        message: error,
        isError: true
      });
      setSimpleActionKind(null);
      return;
    }

    if (simpleActionKind === "kyc") {
      setSimpleResultModal({
        title: "Verification started",
        message: sumsubModalOpen
          ? "The verification form is open. Complete it and then check your status."
          : status || "KYC request submitted successfully.",
        isError: false
      });
      setSimpleActionKind(null);
      return;
    }

    setSimpleResultModal({
      title: verify.ok ? "Status updated" : "Status checked",
      message: verify.ok ? "You're verified and all gated actions are now unlocked." : status || "Status check completed.",
      isError: false
    });
    setSimpleActionKind(null);
  }, [
    busy,
    waitingPacket,
    refreshingStatus,
    syncWaiting,
    simpleActionKind,
    error,
    status,
    verify.ok,
    sumsubModalOpen,
    isAppKitConnected,
    account
  ]);

  async function connectWalletFromSimple() {
    setSimpleResultModal(null);
    setSimpleActionKind(null);
    await connectWallet();
  }

  async function goToKycFromSimple() {
    setSimpleResultModal(null);
    setSimpleActionKind("kyc");
    await goToKyc();
  }

  async function refreshStatusFromSimple() {
    setSimpleResultModal(null);
    setSimpleActionKind("status");
    await refreshStatusWithRetry();
  }

  function parseSumsubStatus(payload: unknown): SumsubStatusSnapshot {
    if (!payload || typeof payload !== "object") {
      return { reviewStatus: "", reviewAnswer: "" };
    }

    const raw = payload as Record<string, unknown>;
    const reviewStatus = String(raw.reviewStatus ?? "").trim().toLowerCase();

    let reviewAnswer = "";
    if (raw.reviewResult && typeof raw.reviewResult === "object") {
      const reviewResult = raw.reviewResult as Record<string, unknown>;
      reviewAnswer = String(reviewResult.reviewAnswer ?? "").trim().toLowerCase();
    }

    return { reviewStatus, reviewAnswer };
  }

  function isTerminalSumsubStatus(payload: unknown): boolean {
    const { reviewStatus, reviewAnswer } = parseSumsubStatus(payload);
    if (reviewStatus === "completed") {
      return true;
    }
    if (reviewAnswer === "green" || reviewAnswer === "red") {
      return true;
    }
    return false;
  }

  async function triggerAutoSyncFromSumsub(payload: unknown): Promise<void> {
    if (!isTerminalSumsubStatus(payload)) {
      return;
    }
    if (!provider || !account || verify.ok) {
      return;
    }
    if (sumsubAutoSyncInFlightRef.current) {
      return;
    }

    const now = Date.now();
    if (now < sumsubAutoSyncCooldownUntilRef.current) {
      return;
    }
    sumsubAutoSyncCooldownUntilRef.current = now + 30_000;
    sumsubAutoSyncInFlightRef.current = true;

    try {
      setStatus("Sumsub review finished. Syncing onchain status...");
      await refreshStatusWithRetry();
    } finally {
      sumsubAutoSyncInFlightRef.current = false;
    }
  }

  async function waitForWorldIdAttestation(userAddress: string): Promise<void> {
    if (!userAddress) {
      return;
    }

    const pollNonce = worldIdPollNonceRef.current + 1;
    worldIdPollNonceRef.current = pollNonce;
    const maxAttempts = 18;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (pollNonce !== worldIdPollNonceRef.current) {
        return;
      }

      const snapshot = await refreshOnchainData(userAddress);
      if (pollNonce !== worldIdPollNonceRef.current) {
        return;
      }

      if (snapshot?.worldIdVerified) {
        setStatus("World ID linked onchain.");
        worldIdPendingAddressRef.current = "";
        return;
      }

      if (attempt < maxAttempts) {
        setStatus(`Waiting for CRE World ID attestation... ${attempt}/${maxAttempts}`);
        await sleep(2500);
      }
    }

    if (pollNonce === worldIdPollNonceRef.current) {
      setStatus("World ID proof accepted. CRE attestation is still pending. You can press Check status.");
    }
  }

  async function handleWorldIdVerify(result: ISuccessResult): Promise<void> {
    if (!provider || !account) {
      throw new Error("Connect wallet first");
    }

    setBusy(true);
    setError("");
    setWorldIdErrorCode("");
    setStatus("Submitting World ID proof onchain...");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        throw new Error("Wrong network for World ID request");
      }

      if (worldIdPrecheckMode !== "off") {
        setStatus("Pre-checking World ID proof...");
        try {
          const precheckResponse = await fetch(worldIdVerifyEndpoint(env.worldIdAppId), {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              ...result,
              action: env.worldIdAction,
              signal_hash: hashSignalToField(account.toLowerCase())
            })
          });

          if (!precheckResponse.ok) {
            const errorBody = await precheckResponse.text();
            const precheckError = parseWorldIdVerifyError(errorBody, precheckResponse.status);
            if (worldIdPrecheckMode === "strict") {
              throw new Error(precheckError);
            }
            setStatus(`World ID pre-check failed (${precheckError}). Submitting onchain request...`);
          }
        } catch (precheckErr) {
          if (worldIdPrecheckMode === "strict") {
            throw precheckErr;
          }
          const message = (precheckErr as Error).message;
          setStatus(`World ID pre-check unavailable (${message}). Submitting onchain request...`);
        }
      }

      const { signer, address } = await getActiveSignerAndAddress();
      const { broker } = makeContracts(signer);

      const tx = await broker.requestWorldIdVerification(
        result.proof,
        result.merkle_root,
        result.nullifier_hash,
        result.verification_level
      );
      const receipt = await tx.wait();

      let requestIdLabel = "";
      const iface = new Interface(kycBrokerAbi);
      for (const log of receipt?.logs ?? []) {
        if (log.address.toLowerCase() !== env.kycBroker.toLowerCase()) {
          continue;
        }

        try {
          const parsed = iface.parseLog(log);
          if (parsed?.name === "WorldIdVerificationRequested") {
            requestIdLabel = `#${(parsed.args.worldIdRequestId as bigint).toString()}`;
            break;
          }
        } catch {
          // Skip unrelated logs.
        }
      }

      if (requestIdLabel) {
        setStatus(`World ID request ${requestIdLabel} submitted. Waiting for CRE verification...`);
      } else {
        setStatus("World ID request submitted onchain. Waiting for CRE verification...");
      }

      worldIdPendingAddressRef.current = address;
      await refreshOnchainData(address);
    } catch (err) {
      worldIdPendingAddressRef.current = "";
      const message = (err as Error).message;
      setStatus(`World ID host verification failed: ${message}`);
      setError(message);
      throw err;
    } finally {
      setBusy(false);
    }
  }

  async function onWorldIdSuccess(): Promise<void> {
    setWorldIdErrorCode("");
    const targetAddress = worldIdPendingAddressRef.current || account;
    setStatus("World ID proof accepted by app. Waiting for CRE onchain attestation...");
    if (targetAddress) {
      void waitForWorldIdAttestation(targetAddress);
    }
  }

  async function onWorldIdError(errorState: IErrorState): Promise<void> {
    const code = String(errorState.code || "unknown_error");
    const detail = errorState.message?.trim();
    setWorldIdErrorCode(code);
    worldIdPendingAddressRef.current = "";
    setStatus(detail ? `World ID declined (${code}): ${detail}` : `World ID declined (${code}).`);
  }

  async function getActiveSignerAndAddress(): Promise<{ signer: ethers.Signer; address: string }> {
    if (!provider) {
      throw new Error("Provider unavailable");
    }

    const signer = await provider.getSigner();
    const address = await signer.getAddress();

    if (!account || account.toLowerCase() !== address.toLowerCase()) {
      const restoredSessionSecret = readSessionSecret(address);
      setAccount(address);
      setSessionSecretKeyHex(restoredSessionSecret);
      sessionSecretKeyRef.current = restoredSessionSecret;
      setPendingDecrypt(null);
      setEncryptionReady(false);
      setSumsubModalOpen(false);
      setWorldIdVerified(false);
    }

    return { signer, address };
  }

  async function ensureExpectedNetwork(providerOverride?: BrowserProvider): Promise<boolean> {
    const activeProvider = providerOverride ?? provider;
    if (!activeProvider) {
      return false;
    }

    const network = await activeProvider.getNetwork();
    const currentChainId = Number(network.chainId);
    setChainId(currentChainId);

    if (env.chainId > 0 && currentChainId !== env.chainId) {
      setStatus(`Wrong network (${currentChainId}). Switch to chain ${env.chainId}.`);
      setError(`Wrong network: expected chainId ${env.chainId}, got ${currentChainId}`);
      return false;
    }

    return true;
  }

  async function connectWallet() {
    setBusy(true);
    setError("");

    try {
      await open({ view: isAppKitConnected ? "Account" : "Connect" });
      setStatus(
        isAppKitConnected
          ? "Account modal opened. You can switch network or disconnect there."
          : "AppKit modal opened. Pick MetaMask in the wallet list."
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function refreshOnchainData(
    forAccount?: string,
    providerOverride?: BrowserProvider
  ): Promise<OnchainSnapshot | null> {
    const activeProvider = providerOverride ?? provider;
    if (!activeProvider) {
      return null;
    }

    const user = (forAccount ?? account).toLowerCase();
    if (!user) {
      return null;
    }

    const onExpectedNetwork = await ensureExpectedNetwork(activeProvider);
    if (!onExpectedNetwork) {
      return null;
    }

    const { registry, broker, accessPass, claimDrop } = makeContracts(activeProvider);

    const [verifyResult, attResult, pubKeyHex, mintedResult, claimedResult] = await Promise.all([
      registry.verifyUser(user, env.policyId),
      registry.attestations(user),
      broker.encryptionPubKey(user),
      accessPass.hasMinted(user),
      claimDrop.claimed(user)
    ]);

    const verifySnapshot = { ok: Boolean(verifyResult[0]), reason: Number(verifyResult[1]) };
    const attFlags = BigInt(attResult[0]);
    const isWorldIdLinked = (attFlags & env.worldIdFlag) === env.worldIdFlag && Boolean(attResult[7]) && !Boolean(attResult[6]);
    setVerify(verifySnapshot);
    setAttestation({
      flags: attFlags.toString(),
      expiration: Number(attResult[1]),
      riskScore: Number(attResult[2]),
      subjectType: Number(attResult[3]),
      revoked: Boolean(attResult[6]),
      exists: Boolean(attResult[7])
    });
    setWorldIdVerified(isWorldIdLinked);
    const hasOnchainEncryptionKey = pubKeyHex !== "0x";
    const localSessionSecret =
      account && account.toLowerCase() === user ? sessionSecretKeyRef.current || readSessionSecret(user) : readSessionSecret(user);
    if (localSessionSecret && account && account.toLowerCase() === user && !sessionSecretKeyRef.current) {
      setSessionSecretKeyHex(localSessionSecret);
      sessionSecretKeyRef.current = localSessionSecret;
    }
    setEncryptionReady(hasOnchainEncryptionKey && Boolean(localSessionSecret));
    if (hasOnchainEncryptionKey && !localSessionSecret) {
      setStatus("Onchain encryption key exists, but local session key is missing. Click Enable encryption again.");
    }
    setHasMinted(Boolean(mintedResult));
    setHasClaimed(Boolean(claimedResult));

    if (env.creIssuer) {
      const allowed = await registry.isIssuer(env.creIssuer);
      setCreIssuerAllowed(Boolean(allowed));
    }

    return {
      verify: verifySnapshot,
      attestationExists: Boolean(attResult[7]),
      worldIdVerified: isWorldIdLinked,
      hasOnchainEncryptionKey
    };
  }

  async function ensureSessionEncryption(signer: ethers.Signer, address: string): Promise<string> {
    const keyPair = generateSessionKeyPairHex();
    const { broker } = makeContracts(signer);
    const tx = await broker.setEncryptionPubKey(keyPair.publicKeyHex);
    await tx.wait();

    sessionSecretKeyRef.current = keyPair.secretKeyHex;
    setSessionSecretKeyHex(keyPair.secretKeyHex);
    writeSessionSecret(address, keyPair.secretKeyHex);
    setEncryptionReady(true);
    setStatus(`Session encryption key stored onchain for ${shortAddress(address)}`);
    return keyPair.secretKeyHex;
  }

  async function enableEncryption() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        return;
      }

      const { signer, address } = await getActiveSignerAndAddress();
      await ensureSessionEncryption(signer, address);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function pollEncryptedPacket(reqId: bigint): Promise<{ ciphertextHex: string; expiresAt: number }> {
    if (!provider) {
      throw new Error("Provider unavailable");
    }

    const { broker } = makeContracts(provider);
    const started = Date.now();

    while (Date.now() - started < 180_000) {
      const packet = await broker.getPacket(reqId);
      const ciphertextHex = packet[1] as string;
      const expiresAt = Number(packet[2]);

      if (ciphertextHex !== "0x") {
        return { ciphertextHex, expiresAt };
      }

      setStatus(`Waiting encrypted SDK token for request ${reqId.toString()}...`);
      await sleep(1000);
    }

    throw new Error("Timed out waiting for encrypted SDK token from CRE");
  }

  function launchSumsub(token: string) {
    if (!window.snsWebSdk) {
      setStatus("Sumsub SDK script missing; token fetched successfully");
      return;
    }

    setSumsubModalOpen(true);

    window.setTimeout(() => {
      if (!window.snsWebSdk) {
        return;
      }

      const sdk = window.snsWebSdk
        .init(token, async () => token)
        .withConf({
          lang: "en",
          email: "",
          phone: ""
        })
        .withOptions({
          addViewportTag: false,
          adaptIframeHeight: true
        })
        .on("idCheck.onApplicantStatusChanged", (payload: unknown) => {
          console.log("Sumsub status update", payload);
          void triggerAutoSyncFromSumsub(payload);
        })
        .build();

      sdk.launch("#sumsub-modal-container");
    }, 25);
  }

  async function autoDecryptAndLaunch(packet: PendingDecryptPacket, secretKeyHexOverride?: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    if (packet.expiresAt > 0 && packet.expiresAt < now) {
      throw new Error("SDK token packet expired. Start verification again.");
    }

    let activeSecretKeyHex = secretKeyHexOverride || sessionSecretKeyRef.current;
    if (!activeSecretKeyHex && packet.owner) {
      activeSecretKeyHex = readSessionSecret(packet.owner);
    }
    if (!activeSecretKeyHex) {
      throw new Error("Missing local session secret key. Click Enable encryption and start verification again.");
    }

    if (!account || account.toLowerCase() !== packet.owner.toLowerCase()) {
      throw new Error(`Wrong wallet for auto-decrypt. Switch to ${shortAddress(packet.owner)}.`);
    }

    if (activeSecretKeyHex !== sessionSecretKeyRef.current) {
      sessionSecretKeyRef.current = activeSecretKeyHex;
      setSessionSecretKeyHex(activeSecretKeyHex);
    }

    const decryptedToken = decryptSessionCiphertextHex(packet.ciphertextHex, activeSecretKeyHex);
    const preview = `${decryptedToken.slice(0, 8)}...${decryptedToken.slice(-6)}`;

    setSdkTokenPreview(preview);
    setPendingDecrypt(null);
    setStatus(`SDK token decrypted (expiresAt=${packet.expiresAt}), launching Sumsub...`);

    launchSumsub(decryptedToken);
    setStatus("Sumsub started automatically. Complete verification flow, then press Sync + refresh status.");
    await refreshOnchainData(packet.owner);
  }

  async function submitKycRequest(signer: ethers.Signer, address: string, sessionSecretHex: string): Promise<void> {
    const { broker } = makeContracts(signer);
    setSyncWaiting(false);

    const tx = await broker.requestKyc(env.kycLevelName);
    const receipt = await tx.wait();

    const iface = new Interface(kycBrokerAbi);
    let newRequestId: bigint | null = null;

    for (const log of receipt?.logs ?? []) {
      if (log.address.toLowerCase() !== env.kycBroker.toLowerCase()) {
        continue;
      }

      try {
        const parsed = iface.parseLog(log);
        if (parsed?.name === "KycRequested") {
          newRequestId = parsed.args.requestId as bigint;
          break;
        }
      } catch {
        // Skip logs from other contracts.
      }
    }

    if (newRequestId === null) {
      throw new Error("Could not read requestId from tx logs");
    }

    setRequestId(newRequestId.toString());
    setSdkTokenPreview("-");
    setPendingDecrypt(null);
    setWaitingPacket(true);
    setStatus(`KYC request submitted (#${newRequestId.toString()}). Waiting for CRE packet...`);

    void (async () => {
      try {
        const packet = await pollEncryptedPacket(newRequestId);
        const pendingPacket = {
          requestId: newRequestId.toString(),
          ciphertextHex: packet.ciphertextHex,
          expiresAt: packet.expiresAt,
          owner: address
        };

        setPendingDecrypt(pendingPacket);
        setStatus("Encrypted SDK token received. Decrypting locally...");
        await autoDecryptAndLaunch(pendingPacket, sessionSecretHex);
      } catch (pollErr) {
        setError((pollErr as Error).message);
        setStatus("Could not auto-decrypt token. Press Start verification again.");
      } finally {
        setWaitingPacket(false);
      }
    })();
  }

  async function startVerification() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    let activeSessionSecret = sessionSecretKeyRef.current;
    if (!activeSessionSecret) {
      activeSessionSecret = readSessionSecret(account);
      if (activeSessionSecret) {
        sessionSecretKeyRef.current = activeSessionSecret;
        setSessionSecretKeyHex(activeSessionSecret);
      }
    }

    if (!activeSessionSecret) {
      setError("Click Enable encryption first to generate a local session key");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        return;
      }

      const { signer, address } = await getActiveSignerAndAddress();
      await submitKycRequest(signer, address, activeSessionSecret);
    } catch (err) {
      setError((err as Error).message);
      setWaitingPacket(false);
    } finally {
      setBusy(false);
    }
  }

  async function goToKyc() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        return;
      }

      const { signer, address } = await getActiveSignerAndAddress();
      let activeSessionSecret = sessionSecretKeyRef.current;
      if (!activeSessionSecret) {
        activeSessionSecret = readSessionSecret(address);
        if (activeSessionSecret) {
          sessionSecretKeyRef.current = activeSessionSecret;
          setSessionSecretKeyHex(activeSessionSecret);
        }
      }

      if (!encryptionReady || !activeSessionSecret) {
        setStatus("Preparing session key...");
        activeSessionSecret = await ensureSessionEncryption(signer, address);
      }

      if (!activeSessionSecret) {
        throw new Error("Could not prepare local session key");
      }

      setStatus("Session key ready. Submitting KYC request...");
      await submitKycRequest(signer, address, activeSessionSecret);
    } catch (err) {
      setError((err as Error).message);
      setWaitingPacket(false);
    } finally {
      setBusy(false);
    }
  }

  async function requestKycSyncFromUser(): Promise<boolean> {
    if (!provider || !account) {
      setError("Connect wallet first");
      return false;
    }

    const onExpectedNetwork = await ensureExpectedNetwork();
    if (!onExpectedNetwork) {
      return false;
    }

    const { signer } = await getActiveSignerAndAddress();
    const { broker } = makeContracts(signer);

    try {
      const tx = await broker.requestKycSync();
      setStatus("Sync request sent onchain. Waiting for confirmation...");
      await tx.wait();
      setStatus("Sync request confirmed. Waiting for CRE status update...");
      return true;
    } catch (err) {
      const message = (err as Error).message;
      if (message.includes("KycSessionBroker: no kyc request")) {
        setStatus("No KYC request found yet. Start verification first.");
        return false;
      }
      if (message.includes("KycSessionBroker: sync cooldown")) {
        setStatus("Sync was requested recently (cooldown). Waiting for CRE update...");
        return false;
      }

      throw err;
    }
  }

  async function refreshStatusWithRetry() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setRefreshingStatus(true);
    setSyncWaiting(true);
    setError("");

    const initialOk = verify.ok;
    const initialReason = verify.reason;
    const maxAttempts = 8;
    let latest: OnchainSnapshot | null = null;

    try {
      if (!verify.ok) {
        await requestKycSyncFromUser();
      }

      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        setStatus(`Refreshing onchain status... ${attempt}/${maxAttempts}`);
        latest = await refreshOnchainData();

        if (!latest) {
          break;
        }

        if (latest.verify.ok || latest.verify.ok !== initialOk || latest.verify.reason !== initialReason) {
          break;
        }

        if (attempt < maxAttempts) {
          await sleep(2200);
        }
      }

      if (!latest) {
        return;
      }

      if (latest.verify.ok) {
        setStatus("Onchain status updated: verifyUser=true.");
        return;
      }

      if (latest.verify.ok !== initialOk || latest.verify.reason !== initialReason) {
        setStatus(`Onchain status changed: ${reasonLabel(latest.verify.reason)}.`);
        return;
      }

      setStatus("No new onchain update yet. CRE sync may still be pending.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSyncWaiting(false);
      setRefreshingStatus(false);
      setBusy(false);
    }
  }

  async function mintAccessPass() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        return;
      }

      const { signer } = await getActiveSignerAndAddress();
      const { accessPass } = makeContracts(signer);
      const tx = await accessPass.mint();
      await tx.wait();
      setStatus("AccessPass minted");
      await refreshOnchainData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function claimDrop() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const onExpectedNetwork = await ensureExpectedNetwork();
      if (!onExpectedNetwork) {
        return;
      }

      const { signer } = await getActiveSignerAndAddress();
      const { claimDrop } = makeContracts(signer);
      const tx = await claimDrop.claim();
      await tx.wait();
      setStatus("Drop claimed");
      await refreshOnchainData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const expectedChainId = env.chainId || 0;
  const networkMismatch = chainId > 0 && expectedChainId > 0 && chainId !== expectedChainId;
  const worldIdConfigured = Boolean(env.worldIdAppId && env.worldIdAction);
  const hasSdkToken = sdkTokenPreview !== "-";
  const connectButtonLabel = isAppKitConnected ? "Connected!" : "Connect wallet";
  const simpleBusy = waitingPacket || refreshingStatus || syncWaiting || (busy && simpleActionKind !== null);
  const simpleProgress = getSimpleProgressCopy(status, waitingPacket, refreshingStatus, syncWaiting);
  const simpleVerificationLabel = verify.ok ? "Verified" : hasSdkToken ? "Review in progress" : "Not verified yet";
  const worldIdVerificationLevel = parseWorldIdVerificationLevel(env.worldIdVerificationLevel);
  const worldIdPrecheckMode = parseWorldIdPrecheckMode(env.worldIdPrecheckMode);
  const simpleNetworkLabel = networkMismatch ? `Wrong network (${chainId})` : `Network ${expectedChainId || "-"}`;
  const attestationExpirationLabel =
    attestation && attestation.expiration > 0 ? new Date(attestation.expiration * 1000).toISOString().slice(0, 10) : "-";
  const accessAssetStatus = verify.ok ? (hasMinted ? "Minted" : "Available") : "Locked";
  const claimAssetStatus = verify.ok ? (hasClaimed ? "Claimed" : "Available") : "Locked";

  return (
    <div className="page page-simple">
      <header className="panel hero reveal hero-simple">
        <div className="hero-top-row">
          <div className="simple-top-actions">
            <button
              className={`top-action-btn top-connect-btn ${isAppKitConnected ? "is-connected" : ""}`}
              onClick={connectWalletFromSimple}
              disabled={busy}
            >
              <span className={`wallet-dot ${isAppKitConnected ? "on" : "off"}`} />
              <span>{connectButtonLabel}</span>
            </button>
            <button
              className="top-action-btn"
              onClick={refreshStatusFromSimple}
              disabled={busy || !account || networkMismatch || waitingPacket}
            >
              {refreshingStatus ? "Checking..." : "Check status"}
            </button>
            <span className={`chain-id-text ${networkMismatch ? "warn" : ""}`}>Chain {chainId || expectedChainId || "-"}</span>
            <span className={`pill ${verify.ok ? "ok" : "warn"}`}>{verify.ok ? "Policy pass" : "Policy blocked"}</span>
          </div>
        </div>

        <div className="hero-main-row">
          <div className="hero-main-copy">
            <h1>
              PassStore <span>+ Sumsub</span>
            </h1>
            <p>No backend. Encrypted SDK token delivery via CRE and policy-gated onchain access.</p>
          </div>
          {!verify.ok ? (
            <div className="hero-main-cta">
              <button
                className="simple-btn primary hero-cta-btn"
                onClick={goToKycFromSimple}
                disabled={busy || !account || networkMismatch || waitingPacket}
              >
                Go to KYC
              </button>
            </div>
          ) : null}
        </div>
      </header>

      <div className="simple-layout reveal">
        <section className="simple-panel">
          <h2 className="simple-section-title">Identity Access</h2>
          <div className="simple-card">
            <p>{verify.ok ? "You are verified. Protected actions are now available." : "Complete verification to unlock access."}</p>
            <div className="simple-identity-box">
              <div className="simple-attestation">
                <div className="simple-att-item">
                  <span>Exists</span>
                  <strong>{String(attestation?.exists ?? false)}</strong>
                </div>
                <div className="simple-att-item">
                  <span>Revoked</span>
                  <strong>{String(attestation?.revoked ?? false)}</strong>
                </div>
                <div className="simple-att-item">
                  <span>Flags</span>
                  <strong>{attestation?.flags ?? "0"}</strong>
                </div>
                <div className="simple-att-item">
                  <span>Expires</span>
                  <strong>{attestationExpirationLabel}</strong>
                </div>
                <div className="simple-att-item">
                  <span>Risk</span>
                  <strong>{attestation?.riskScore ?? 0}</strong>
                </div>
                <div className="simple-att-item">
                  <span>Subject</span>
                  <strong>{attestation?.subjectType ?? 0}</strong>
                </div>
              </div>
              <div className="simple-tags">
                <span className="simple-tag">{account ? shortAddress(account) : "Wallet not connected"}</span>
                <span className={`simple-tag ${verify.ok ? "ok" : "warn"}`}>{simpleVerificationLabel}</span>
                <span className={`simple-tag ${networkMismatch ? "warn" : ""}`}>{simpleNetworkLabel}</span>
              </div>
            </div>
          </div>

          {error ? <div className="simple-error">Error: {error}</div> : null}
          {sumsubModalOpen ? <p className="simple-note">Verification form is open. Complete it and then press Check status.</p> : null}
          {worldIdConfigured ? (
            <div className="simple-worldid-row">
              <IDKitWidget
                app_id={env.worldIdAppId as `app_${string}`}
                action={env.worldIdAction}
                signal={account.toLowerCase()}
                verification_level={worldIdVerificationLevel}
                handleVerify={handleWorldIdVerify}
                onSuccess={onWorldIdSuccess}
                onError={onWorldIdError}
              >
                {({ open }: { open: () => void }) => (
                  <button
                    className={`simple-btn ${worldIdVerified ? "secondary" : "primary"}`}
                    onClick={open}
                    disabled={busy || !account || networkMismatch}
                  >
                    {worldIdVerified ? "World ID verified" : "Verify with World ID"}
                  </button>
                )}
              </IDKitWidget>
              <span className={`simple-worldid-badge ${worldIdVerified ? "ok" : "warn"}`}>
                {worldIdVerified ? "World ID: linked" : "World ID: pending"}
              </span>
            </div>
          ) : null}
          {worldIdErrorCode ? <p className="simple-note">World ID error code: {worldIdErrorCode}</p> : null}
        </section>
        <section className="simple-panel simple-assets-panel">
          <h2>Available assets</h2>
          <p>Demo has 2 gated assets.</p>
          <div className="simple-asset-row">
            <div className="simple-asset-meta">
              <span>AccessPass</span>
              <strong>{accessAssetStatus}</strong>
            </div>
            <button
              className="simple-asset-btn"
              onClick={mintAccessPass}
              disabled={busy || !account || networkMismatch || !verify.ok || hasMinted}
            >
              {hasMinted ? "Received" : "Get"}
            </button>
          </div>
          <div className="simple-asset-row">
            <div className="simple-asset-meta">
              <span>ClaimDrop</span>
              <strong>{claimAssetStatus}</strong>
            </div>
            <button
              className="simple-asset-btn"
              onClick={claimDrop}
              disabled={busy || !account || networkMismatch || !verify.ok || hasClaimed}
            >
              {hasClaimed ? "Claimed" : "Claim"}
            </button>
          </div>
        </section>
      </div>

      {simpleBusy ? (
        <div className="simple-loading-backdrop">
          <div className="simple-loading-card">
            <div className="simple-spinner" />
            <h3>{simpleProgress.title}</h3>
            <p>{simpleProgress.message}</p>
            <span>{status}</span>
          </div>
        </div>
      ) : null}

      {simpleResultModal ? (
        <div className="simple-result-backdrop">
          <div className={`simple-result-card ${simpleResultModal.isError ? "is-error" : ""}`}>
            <h3>{simpleResultModal.title}</h3>
            <p>{simpleResultModal.message}</p>
            <button className="simple-btn primary" onClick={() => setSimpleResultModal(null)}>
              OK
            </button>
          </div>
        </div>
      ) : null}

      {sumsubModalOpen ? (
        <div className="modal-backdrop" onClick={() => setSumsubModalOpen(false)}>
          <div className="modal-card reveal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <h3>Sumsub Verification</h3>
              <button className="btn" onClick={() => setSumsubModalOpen(false)}>
                Close
              </button>
            </div>
            <div id="sumsub-modal-container" className="sumsub modal-sumsub" />
          </div>
        </div>
      ) : null}
    </div>
  );
}
