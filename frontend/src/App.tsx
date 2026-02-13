import { useEffect, useMemo, useRef, useState } from "react";
import { Contract, BrowserProvider, Interface, ethers } from "ethers";
import { useAppKit, useAppKitAccount, useAppKitProvider } from "@reown/appkit/react";
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
  const [view, setView] = useState<"classic" | "quick" | "simple">("classic");
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
  const [simpleActionKind, setSimpleActionKind] = useState<SimpleActionKind | null>(null);
  const [simpleResultModal, setSimpleResultModal] = useState<SimpleResultModal | null>(null);
  const { open } = useAppKit();
  const { address: appKitAddress, isConnected: isAppKitConnected } = useAppKitAccount({ namespace: "eip155" });
  const { walletProvider } = useAppKitProvider<WalletProviderLike>("eip155");
  const simpleWasBusyRef = useRef<boolean>(false);
  const sessionSecretKeyRef = useRef<string>("");

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
    if (view === "simple") {
      document.body.classList.add(lightClass);
    } else {
      document.body.classList.remove(lightClass);
    }

    return () => {
      document.body.classList.remove(lightClass);
    };
  }, [view]);

  useEffect(() => {
    if (!appKitAddress || !isAppKitConnected) {
      if (account) {
        setAccount("");
        setChainId(0);
        setSessionSecretKeyHex("");
        sessionSecretKeyRef.current = "";
        setPendingDecrypt(null);
        setEncryptionReady(false);
        setSumsubModalOpen(false);
        setStatus("Wallet disconnected");
      }

      return;
    }

    if (!account || account.toLowerCase() !== appKitAddress.toLowerCase()) {
      const restoredSessionSecret = readSessionSecret(appKitAddress);
      setAccount(appKitAddress);
      setSessionSecretKeyHex(restoredSessionSecret);
      sessionSecretKeyRef.current = restoredSessionSecret;
      setPendingDecrypt(null);
      setEncryptionReady(false);
      setSumsubModalOpen(false);
      setStatus("Wallet connected");
      window.setTimeout(() => {
        void refreshOnchainData(appKitAddress);
      }, 0);
    }
  }, [account, appKitAddress, isAppKitConnected, provider]);

  useEffect(() => {
    if (view !== "simple") {
      simpleWasBusyRef.current = false;
      return;
    }

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
    view,
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
    setVerify(verifySnapshot);
    setAttestation({
      flags: attResult[0].toString(),
      expiration: Number(attResult[1]),
      riskScore: Number(attResult[2]),
      subjectType: Number(attResult[3]),
      revoked: Boolean(attResult[6]),
      exists: Boolean(attResult[7])
    });
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
  const verifyText = `${String(verify.ok)} (${reasonLabel(verify.reason)})`;
  const hasRequest = requestId !== "-";
  const hasSdkToken = sdkTokenPreview !== "-";
  const waitingDecrypt = Boolean(pendingDecrypt);
  const connectButtonLabel = isAppKitConnected ? "Connected!" : "Connect wallet";
  const simpleBusy =
    view === "simple" && (waitingPacket || refreshingStatus || syncWaiting || (busy && simpleActionKind !== null));
  const simpleProgress = getSimpleProgressCopy(status, waitingPacket, refreshingStatus, syncWaiting);
  const simpleVerificationLabel = verify.ok ? "Verified" : hasSdkToken ? "Review in progress" : "Not verified yet";
  const simpleNetworkLabel = networkMismatch ? `Wrong network (${chainId})` : `Network ${expectedChainId || "-"}`;
  const attestationExpirationLabel =
    attestation && attestation.expiration > 0 ? new Date(attestation.expiration * 1000).toISOString().slice(0, 10) : "-";
  const accessAssetStatus = verify.ok ? (hasMinted ? "Minted" : "Available") : "Locked";
  const claimAssetStatus = verify.ok ? (hasClaimed ? "Claimed" : "Available") : "Locked";

  return (
    <div className={`page ${view === "simple" ? "page-simple" : ""}`}>
      {view === "simple" ? null : <div className="mesh mesh-a" />}
      {view === "simple" ? null : <div className="mesh mesh-b" />}

      <header className={`panel hero reveal ${view === "simple" ? "hero-simple" : ""}`}>
        {view === "simple" ? (
          <>
            <div className="hero-top-row">
              <div className="view-switch view-switch-inline">
                <button className="switch-btn" onClick={() => setView("classic")}>
                  Classic Flow
                </button>
                <button className="switch-btn" onClick={() => setView("quick")}>
                  Quick KYC
                </button>
                <button className="switch-btn active" onClick={() => setView("simple")}>
                  Simple UX
                </button>
              </div>
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
          </>
        ) : (
          <div className="hero-row">
            <p className="eyebrow">Trust Registry MVP</p>
            <span className={`pill ${verify.ok ? "ok" : "warn"}`}>{verify.ok ? "Policy pass" : "Policy blocked"}</span>
          </div>
        )}
        {view === "simple" ? (
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
        ) : (
          <>
            <h1>
              PassStore <span>+ Sumsub</span>
            </h1>
            <p>No backend. Encrypted SDK token delivery via CRE and policy-gated onchain access.</p>
            <div className="view-switch">
              <button className={`switch-btn ${view === "classic" ? "active" : ""}`} onClick={() => setView("classic")}>
                Classic Flow
              </button>
              <button className={`switch-btn ${view === "quick" ? "active" : ""}`} onClick={() => setView("quick")}>
                Quick KYC
              </button>
              <button className="switch-btn" onClick={() => setView("simple")}>
                Simple UX
              </button>
            </div>
          </>
        )}
      </header>

      {view === "simple" ? (
        <>
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
        </>
      ) : (
        <div className="layout">
        <section className="panel reveal">
          <div className="section-head">
            <h2>User Flow</h2>
            <span className={`pill ${networkMismatch ? "warn" : "ok"}`}>
              {networkMismatch ? `Wrong network (${chainId})` : `Chain ${chainId || "-"}`}
            </span>
          </div>

          {view === "classic" ? (
            <>
              <div className="flow-block">
                <h3>Sequence</h3>
                <div className="steps">
                  <article className={`step ${account && !networkMismatch ? "done" : account ? "warn" : "active"}`}>
                    <span className="step-index">1</span>
                    <div className="step-content">
                      <p className="step-title">Connect wallet on chain {expectedChainId || "31337"}</p>
                      <p className="step-note">Use Localhost 8545 / chainId 31337 for this demo.</p>
                    </div>
                    <span className="step-badge">{account ? (networkMismatch ? "wrong network" : "done") : "now"}</span>
                  </article>

                  <article className={`step ${encryptionReady ? "done" : account ? "active" : "pending"}`}>
                    <span className="step-index">2</span>
                    <div className="step-content">
                      <p className="step-title">Generate session key</p>
                      <p className="step-note">Click Enable encryption to create a local session key and store pubkey onchain.</p>
                    </div>
                    <span className="step-badge">{encryptionReady ? "done" : account ? "now" : "pending"}</span>
                  </article>

                  <article className={`step ${hasSdkToken ? "done" : hasRequest ? "active" : "pending"}`}>
                    <span className="step-index">3</span>
                    <div className="step-content">
                      <p className="step-title">Start KYC and fetch SDK token</p>
                      <p className="step-note">Request session, wait CRE token packet, decrypt token locally in browser.</p>
                    </div>
                    <span className="step-badge">
                      {hasSdkToken ? "done" : waitingPacket ? "waiting CRE" : waitingDecrypt ? "retry" : hasRequest ? "pending" : "pending"}
                    </span>
                  </article>

                  <article className={`step ${verify.ok ? "done" : hasSdkToken ? "active" : "pending"}`}>
                    <span className="step-index">4</span>
                    <div className="step-content">
                      <p className="step-title">Complete Sumsub and request onchain sync</p>
                      <p className="step-note">After GREEN, press Sync + refresh status to trigger CRE update.</p>
                    </div>
                    <span className="step-badge">{verify.ok ? "done" : hasSdkToken ? "waiting review" : "pending"}</span>
                  </article>
                </div>
              </div>

              <div className="button-grid">
                <button className="btn strong" onClick={connectWallet} disabled={busy}>
                  {connectButtonLabel}
                </button>
                <button
                  className="btn"
                  onClick={refreshStatusWithRetry}
                  disabled={busy || !account || networkMismatch || waitingPacket}
                >
                  {refreshingStatus ? "Refreshing..." : "Sync + refresh status"}
                </button>
                <button
                  className="btn"
                  onClick={enableEncryption}
                  disabled={busy || !account || networkMismatch || waitingPacket}
                >
                  Enable encryption
                </button>
                <button
                  className="btn strong"
                  onClick={startVerification}
                  disabled={busy || !account || !encryptionReady || networkMismatch || waitingPacket}
                >
                  Start verification
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="flow-block quick-flow">
                <h3>Quick KYC Flow</h3>
                <div className="steps">
                  <article className={`step ${account && !networkMismatch ? "done" : account ? "warn" : "active"}`}>
                    <span className="step-index">1</span>
                    <div className="step-content">
                      <p className="step-title">Connect wallet</p>
                      <p className="step-note">Use chain {expectedChainId || "31337"} to continue.</p>
                    </div>
                    <span className="step-badge">{account ? (networkMismatch ? "wrong network" : "done") : "now"}</span>
                  </article>
                  <article className={`step ${hasRequest || waitingPacket ? "active" : account ? "pending" : "pending"}`}>
                    <span className="step-index">2</span>
                    <div className="step-content">
                      <p className="step-title">Go to KYC</p>
                      <p className="step-note">One click runs: enable encryption -&gt; start verification.</p>
                    </div>
                    <span className="step-badge">{waitingPacket ? "waiting CRE" : hasRequest ? "requested" : "pending"}</span>
                  </article>
                  <article className={`step ${hasSdkToken || sumsubModalOpen ? "active" : "pending"}`}>
                    <span className="step-index">3</span>
                    <div className="step-content">
                      <p className="step-title">Complete Sumsub in modal</p>
                      <p className="step-note">WebSDK opens automatically in modal window.</p>
                    </div>
                    <span className="step-badge">{sumsubModalOpen ? "open" : hasSdkToken ? "started" : "pending"}</span>
                  </article>
                  <article className={`step ${verify.ok ? "done" : syncWaiting || hasSdkToken ? "active" : "pending"}`}>
                    <span className="step-index">4</span>
                    <div className="step-content">
                      <p className="step-title">Wait onchain sync</p>
                      <p className="step-note">Button sends onchain sync request, then UI waits for updated verifyUser.</p>
                    </div>
                    <span className="step-badge">{verify.ok ? "done" : syncWaiting ? "syncing..." : "pending"}</span>
                  </article>
                </div>
              </div>

              <div className="button-grid quick-grid">
                <button className="btn strong" onClick={connectWallet} disabled={busy}>
                  {connectButtonLabel}
                </button>
                <button
                  className={`btn strong quick-cta ${account && !busy && !networkMismatch ? "pulse" : ""}`}
                  onClick={goToKyc}
                  disabled={busy || !account || networkMismatch || waitingPacket}
                >
                  Go to KYC
                </button>
              </div>
              <button className="link-btn" onClick={refreshStatusWithRetry} disabled={busy || !account || networkMismatch}>
                {refreshingStatus ? "Checking status..." : "Sync + check status"}
              </button>
            </>
          )}

          <p className="muted">Connect wallet opens default AppKit modal (installed wallets are marked there).</p>

          <div className="level-lock">
            <span className="level-label">KYC Level (ENV)</span>
            <span className="level-pill">{env.kycLevelName}</span>
          </div>

          <div className="kv-grid">
            <div className="kv">
              <span>Account</span>
              <strong>{shortAddress(account)}</strong>
            </div>
            <div className="kv">
              <span>Expected Chain</span>
              <strong>{expectedChainId || "-"}</strong>
            </div>
            <div className="kv">
              <span>Encryption</span>
              <strong>{encryptionReady ? "Enabled" : "Missing"}</strong>
            </div>
            <div className="kv">
              <span>Request ID</span>
              <strong>{requestId}</strong>
            </div>
            <div className="kv">
              <span>SDK token</span>
              <strong>{sdkTokenPreview}</strong>
            </div>
            <div className="kv">
              <span>verifyUser</span>
              <strong>{verifyText}</strong>
            </div>
          </div>

          <div className={`status-box ${refreshingStatus || syncWaiting || waitingPacket ? "live" : ""}`}>
            <span className={`status-dot ${refreshingStatus || syncWaiting || waitingPacket ? "spin" : ""}`} />
            Status: {status}
          </div>
          {error ? <div className="error">Error: {error}</div> : null}
          {sumsubModalOpen ? <p className="muted">Sumsub WebSDK is open in modal.</p> : null}
        </section>

        <div className="stack">
          <section className="panel reveal delay-1">
            <h2>Demo Apps</h2>
            <div className="button-grid single">
              <button className="btn strong" onClick={mintAccessPass} disabled={busy || !account || networkMismatch}>
                Mint AccessPass
              </button>
              <button className="btn" onClick={claimDrop} disabled={busy || !account || networkMismatch}>
                Claim Drop
              </button>
            </div>
            <div className="kv-grid compact">
              <div className="kv">
                <span>AccessPass minted</span>
                <strong>{String(hasMinted)}</strong>
              </div>
              <div className="kv">
                <span>ClaimDrop claimed</span>
                <strong>{String(hasClaimed)}</strong>
              </div>
            </div>
          </section>

          <section className="panel reveal delay-2">
            <h2>Attestation Snapshot</h2>
            {attestation ? (
              <div className="kv-grid compact">
                <div className="kv">
                  <span>Exists</span>
                  <strong>{String(attestation.exists)}</strong>
                </div>
                <div className="kv">
                  <span>Revoked</span>
                  <strong>{String(attestation.revoked)}</strong>
                </div>
                <div className="kv">
                  <span>Flags</span>
                  <strong>{attestation.flags}</strong>
                </div>
                <div className="kv">
                  <span>Expiration</span>
                  <strong>{attestation.expiration > 0 ? new Date(attestation.expiration * 1000).toISOString() : "-"}</strong>
                </div>
                <div className="kv">
                  <span>Risk score</span>
                  <strong>{attestation.riskScore}</strong>
                </div>
                <div className="kv">
                  <span>Subject type</span>
                  <strong>{attestation.subjectType}</strong>
                </div>
              </div>
            ) : (
              <p className="muted">No attestation loaded yet.</p>
            )}
          </section>

          <section className="panel reveal delay-3">
            <h2>Admin (read-only)</h2>
            <div className="kv-grid compact">
              <div className="kv">
                <span>CRE issuer</span>
                <strong>{env.creIssuer ?? "not set"}</strong>
              </div>
              <div className="kv">
                <span>Issuer allowed</span>
                <strong>{creIssuerAllowed === null ? "unknown" : String(creIssuerAllowed)}</strong>
              </div>
              <div className="kv">
                <span>Policy ID</span>
                <strong>{env.policyId.toString()}</strong>
              </div>
              <div className="kv">
                <span>Registry</span>
                <strong>{env.passRegistry}</strong>
              </div>
              <div className="kv">
                <span>Broker</span>
                <strong>{env.kycBroker}</strong>
              </div>
            </div>
          </section>
        </div>
      </div>
      )}

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

      {view === "simple" && simpleResultModal ? (
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
