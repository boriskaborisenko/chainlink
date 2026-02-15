import { useMemo, useState } from "react";
import { Contract, BrowserProvider, Interface, ethers } from "ethers";
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

export default function App() {
  const [account, setAccount] = useState<string>("");
  const [chainId, setChainId] = useState<number>(0);
  const [busy, setBusy] = useState<boolean>(false);
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

  const provider = useMemo(() => {
    if (!window.ethereum) {
      return null;
    }

    return new BrowserProvider(window.ethereum);
  }, []);

  async function getActiveSignerAndAddress(): Promise<{ signer: ethers.Signer; address: string }> {
    if (!provider) {
      throw new Error("Provider unavailable");
    }

    const signer = await provider.getSigner();
    const address = await signer.getAddress();

    if (!account || account.toLowerCase() !== address.toLowerCase()) {
      setAccount(address);
      setSessionSecretKeyHex("");
      setPendingDecrypt(null);
      setEncryptionReady(false);
    }

    return { signer, address };
  }

  async function ensureExpectedNetwork(): Promise<boolean> {
    if (!provider) {
      return false;
    }

    const network = await provider.getNetwork();
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
    if (!window.ethereum || !provider) {
      setError("EVM wallet provider is required");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const accounts = (await window.ethereum.request({ method: "eth_requestAccounts" })) as string[];
      const selected = accounts[0] ?? "";
      setAccount(selected);

      const network = await provider.getNetwork();
      const currentChainId = Number(network.chainId);
      setChainId(currentChainId);

      if (env.chainId > 0 && currentChainId !== env.chainId) {
        setStatus(`Wallet connected, but wrong network (${currentChainId}). Switch to ${env.chainId}.`);
        setError(`Wrong network: expected chainId ${env.chainId}, got ${currentChainId}`);
        return;
      }

      setStatus("Wallet connected");
      await refreshOnchainData(selected);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function refreshOnchainData(forAccount?: string) {
    if (!provider) {
      return;
    }

    const user = (forAccount ?? account).toLowerCase();
    if (!user) {
      return;
    }

    const onExpectedNetwork = await ensureExpectedNetwork();
    if (!onExpectedNetwork) {
      return;
    }

    const { registry, broker, accessPass, claimDrop } = makeContracts(provider);

    const [verifyResult, attResult, pubKeyHex, mintedResult, claimedResult] = await Promise.all([
      registry.verifyUser(user, env.policyId),
      registry.attestations(user),
      broker.encryptionPubKey(user),
      accessPass.hasMinted(user),
      claimDrop.claimed(user)
    ]);

    setVerify({ ok: Boolean(verifyResult[0]), reason: Number(verifyResult[1]) });
    setAttestation({
      flags: attResult[0].toString(),
      expiration: Number(attResult[1]),
      riskScore: Number(attResult[2]),
      subjectType: Number(attResult[3]),
      revoked: Boolean(attResult[6]),
      exists: Boolean(attResult[7])
    });
    const hasOnchainEncryptionKey = pubKeyHex !== "0x";
    setEncryptionReady(hasOnchainEncryptionKey && Boolean(sessionSecretKeyHex));
    if (hasOnchainEncryptionKey && !sessionSecretKeyHex) {
      setStatus("Onchain encryption key exists, but local session key is missing. Click Enable encryption again.");
    }
    setHasMinted(Boolean(mintedResult));
    setHasClaimed(Boolean(claimedResult));

    if (env.creIssuer) {
      const allowed = await registry.isIssuer(env.creIssuer);
      setCreIssuerAllowed(Boolean(allowed));
    }
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
      const keyPair = generateSessionKeyPairHex();

      const { broker } = makeContracts(signer);
      const tx = await broker.setEncryptionPubKey(keyPair.publicKeyHex);
      await tx.wait();

      setSessionSecretKeyHex(keyPair.secretKeyHex);
      setStatus(`Session encryption key stored onchain for ${shortAddress(address)}`);
      setEncryptionReady(true);
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

    sdk.launch("#sumsub-websdk-container");
  }

  async function autoDecryptAndLaunch(packet: PendingDecryptPacket): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    if (packet.expiresAt > 0 && packet.expiresAt < now) {
      throw new Error("SDK token packet expired. Start verification again.");
    }

    if (!sessionSecretKeyHex) {
      throw new Error("Missing local session secret key. Click Enable encryption and start verification again.");
    }

    if (!account || account.toLowerCase() !== packet.owner.toLowerCase()) {
      throw new Error(`Wrong wallet for auto-decrypt. Switch to ${shortAddress(packet.owner)}.`);
    }

    const decryptedToken = decryptSessionCiphertextHex(packet.ciphertextHex, sessionSecretKeyHex);
    const preview = `${decryptedToken.slice(0, 8)}...${decryptedToken.slice(-6)}`;

    setSdkTokenPreview(preview);
    setPendingDecrypt(null);
    setStatus(`SDK token decrypted (expiresAt=${packet.expiresAt}), launching Sumsub...`);

    launchSumsub(decryptedToken);
    setStatus("Sumsub started automatically. Complete verification flow, then press Refresh status.");
    await refreshOnchainData(packet.owner);
  }

  async function startVerification() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    if (!sessionSecretKeyHex) {
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
      const { broker } = makeContracts(signer);

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
          await autoDecryptAndLaunch(pendingPacket);
        } catch (pollErr) {
          setError((pollErr as Error).message);
          setStatus("Could not auto-decrypt token. Press Start verification again.");
        } finally {
          setWaitingPacket(false);
        }
      })();
    } catch (err) {
      setError((err as Error).message);
      setWaitingPacket(false);
    } finally {
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

  return (
    <div className="page">
      <div className="mesh mesh-a" />
      <div className="mesh mesh-b" />

      <header className="panel hero reveal">
        <div className="hero-row">
          <p className="eyebrow">Trust Registry MVP</p>
          <span className={`pill ${verify.ok ? "ok" : "warn"}`}>{verify.ok ? "Policy pass" : "Policy blocked"}</span>
        </div>
        <h1>
          PassStore <span>+ Sumsub</span>
        </h1>
        <p>
          No custom backend: encrypted SDK token packets onchain, CRE workers for issuance and status sync,
          and policy-gated onchain apps. Provider layer is extensible: Sumsub now, other KYC providers next.
        </p>
        <div className="chip-row">
          <span className="chip">React + Vite</span>
          <span className="chip">Chainlink CRE</span>
          <span className="chip">Sumsub WebSDK</span>
          <span className="chip">Provider-agnostic</span>
          <span className="chip">No PII onchain</span>
        </div>
      </header>

      <div className="layout">
        <section className="panel reveal">
          <div className="section-head">
            <h2>User Flow</h2>
            <span className={`pill ${networkMismatch ? "warn" : "ok"}`}>
              {networkMismatch ? `Wrong network (${chainId})` : `Chain ${chainId || "-"}`}
            </span>
          </div>
          {error ? (
            <div className="error-top">
              <strong>Issue:</strong> {error}
            </div>
          ) : null}

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
                  <p className="step-title">Complete Sumsub and wait sync</p>
                  <p className="step-note">After GREEN, verifyUser becomes true and gated actions unlock.</p>
                </div>
                <span className="step-badge">{verify.ok ? "done" : hasSdkToken ? "waiting review" : "pending"}</span>
              </article>
            </div>
          </div>

          <div className="button-grid">
            <button className="btn strong" onClick={connectWallet} disabled={busy}>
              Connect wallet
            </button>
            <button className="btn" onClick={() => refreshOnchainData()} disabled={busy || !account || networkMismatch}>
              Refresh status
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

          <div className="status-box">Status: {status}</div>
          <div id="sumsub-websdk-container" className="sumsub" />
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
    </div>
  );
}
