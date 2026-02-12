import { useMemo, useState } from "react";
import { Contract, BrowserProvider, Interface, ethers } from "ethers";
import { passRegistryAbi } from "./abi/passRegistry";
import { kycBrokerAbi } from "./abi/kycBroker";
import { accessPassAbi } from "./abi/accessPass";
import { claimDropAbi } from "./abi/claimDrop";
import { env } from "./lib/env";

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
  const [levelName, setLevelName] = useState<string>("basic-kyc");
  const [requestId, setRequestId] = useState<string>("-");
  const [sdkTokenPreview, setSdkTokenPreview] = useState<string>("-");
  const [verify, setVerify] = useState<VerifySnapshot>({ ok: false, reason: 1 });
  const [attestation, setAttestation] = useState<AttestationSnapshot | null>(null);
  const [encryptionReady, setEncryptionReady] = useState<boolean>(false);
  const [hasMinted, setHasMinted] = useState<boolean>(false);
  const [hasClaimed, setHasClaimed] = useState<boolean>(false);
  const [creIssuerAllowed, setCreIssuerAllowed] = useState<boolean | null>(null);

  const provider = useMemo(() => {
    if (!window.ethereum) {
      return null;
    }

    return new BrowserProvider(window.ethereum);
  }, []);

  async function connectWallet() {
    if (!window.ethereum || !provider) {
      setError("MetaMask is required");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const accounts = (await window.ethereum.request({ method: "eth_requestAccounts" })) as string[];
      const selected = accounts[0] ?? "";
      setAccount(selected);

      const network = await provider.getNetwork();
      setChainId(Number(network.chainId));

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
    setEncryptionReady(pubKeyHex !== "0x");
    setHasMinted(Boolean(mintedResult));
    setHasClaimed(Boolean(claimedResult));

    if (env.creIssuer) {
      const allowed = await registry.isIssuer(env.creIssuer);
      setCreIssuerAllowed(Boolean(allowed));
    }
  }

  async function enableEncryption() {
    if (!window.ethereum || !provider || !account) {
      setError("Connect wallet first");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const pubKey = (await window.ethereum.request({
        method: "eth_getEncryptionPublicKey",
        params: [account]
      })) as string;

      const signer = await provider.getSigner();
      const { broker } = makeContracts(signer);
      const tx = await broker.setEncryptionPubKey(ethers.hexlify(ethers.toUtf8Bytes(pubKey)));
      await tx.wait();

      setStatus("Encryption public key stored onchain");
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
      await sleep(4000);
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

  async function startVerification() {
    if (!provider || !account) {
      setError("Connect wallet first");
      return;
    }

    if (!encryptionReady) {
      setError("Enable encryption before starting verification");
      return;
    }

    setBusy(true);
    setError("");

    try {
      const signer = await provider.getSigner();
      const { broker } = makeContracts(signer);

      const tx = await broker.requestKyc(levelName);
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
      setStatus(`KYC request submitted (#${newRequestId.toString()})`);

      const packet = await pollEncryptedPacket(newRequestId);
      const encryptedPayload = ethers.toUtf8String(packet.ciphertextHex);

      const decryptedToken = (await window.ethereum?.request({
        method: "eth_decrypt",
        params: [encryptedPayload, account]
      })) as string;

      if (!decryptedToken) {
        throw new Error("Decryption failed");
      }

      const preview = `${decryptedToken.slice(0, 8)}...${decryptedToken.slice(-6)}`;
      setSdkTokenPreview(preview);
      setStatus(`SDK token decrypted (expiresAt=${packet.expiresAt})`);

      launchSumsub(decryptedToken);

      const txConsume = await broker.markConsumed(newRequestId);
      await txConsume.wait();
    } catch (err) {
      setError((err as Error).message);
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
      const signer = await provider.getSigner();
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
      const signer = await provider.getSigner();
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

  return (
    <div className="page">
      <header className="hero">
        <h1>PassStore + Sumsub (No Backend)</h1>
        <p>
          Frontend + Smart Contracts + Chainlink CRE only. SDK token delivery happens onchain in encrypted form.
        </p>
      </header>

      <section className="card">
        <h2>User Flow</h2>
        <div className="grid two">
          <button onClick={connectWallet} disabled={busy}>
            Connect wallet
          </button>
          <button onClick={() => refreshOnchainData()} disabled={busy || !account}>
            Refresh status
          </button>
          <button onClick={enableEncryption} disabled={busy || !account}>
            Enable encryption
          </button>
          <button onClick={startVerification} disabled={busy || !account || !encryptionReady}>
            Start verification
          </button>
        </div>

        <label>
          Sumsub level
          <input value={levelName} onChange={(e) => setLevelName(e.target.value)} />
        </label>

        <div className="meta">
          <div>Account: {account || "-"}</div>
          <div>Chain ID: {chainId || "-"}</div>
          <div>Expected Chain ID: {env.chainId || "-"}</div>
          <div>Encryption key set: {String(encryptionReady)}</div>
          <div>Last requestId: {requestId}</div>
          <div>SDK token: {sdkTokenPreview}</div>
          <div>
            verifyUser: {String(verify.ok)} ({reasonLabel(verify.reason)})
          </div>
          <div>Status: {status}</div>
        </div>

        {error ? <div className="error">Error: {error}</div> : null}
        <div id="sumsub-websdk-container" className="sumsub" />
      </section>

      <section className="card">
        <h2>Demo Apps</h2>
        <div className="grid two">
          <button onClick={mintAccessPass} disabled={busy || !account}>
            Mint AccessPass
          </button>
          <button onClick={claimDrop} disabled={busy || !account}>
            Claim Drop
          </button>
        </div>
        <div className="meta">
          <div>AccessPass minted: {String(hasMinted)}</div>
          <div>ClaimDrop claimed: {String(hasClaimed)}</div>
        </div>
      </section>

      <section className="card">
        <h2>Attestation Snapshot</h2>
        {attestation ? (
          <div className="meta">
            <div>Exists: {String(attestation.exists)}</div>
            <div>Revoked: {String(attestation.revoked)}</div>
            <div>Flags: {attestation.flags}</div>
            <div>
              Expiration: {attestation.expiration > 0 ? new Date(attestation.expiration * 1000).toISOString() : "-"}
            </div>
            <div>Risk score: {attestation.riskScore}</div>
            <div>Subject type: {attestation.subjectType}</div>
          </div>
        ) : (
          <div>No attestation loaded yet.</div>
        )}
      </section>

      <section className="card">
        <h2>Admin (read-only)</h2>
        <div className="meta">
          <div>CRE issuer: {env.creIssuer ?? "not set"}</div>
          <div>Issuer allowed in registry: {creIssuerAllowed === null ? "unknown" : String(creIssuerAllowed)}</div>
          <div>Policy ID: {env.policyId.toString()}</div>
          <div>Registry: {env.passRegistry}</div>
          <div>Broker: {env.kycBroker}</div>
        </div>
      </section>
    </div>
  );
}
