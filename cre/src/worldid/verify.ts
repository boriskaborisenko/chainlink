import { ethers } from "ethers";
import { getRegistry } from "../clients/chain.js";
import { config } from "../config.js";

export type WorldIdProof = {
  proof: string;
  merkle_root: string;
  nullifier_hash: string;
  verification_level: string;
};

type WorldIdVerifyError = {
  code?: string;
  detail?: string;
};

function hashSignalToField(signal: string): string {
  const normalized = signal.trim();
  // Match IDKit cloud verification hashing:
  // hex-like signals (wallet addresses) are hashed as raw bytes.
  const hashInput = ethers.isHexString(normalized) ? normalized : ethers.toUtf8Bytes(normalized);
  const fullHash = BigInt(ethers.keccak256(hashInput));
  const shifted = fullHash >> 8n;
  return `0x${shifted.toString(16).padStart(64, "0")}`;
}

function worldIdVerifyEndpoint(): string {
  if (config.worldIdVerifyEndpoint) {
    return config.worldIdVerifyEndpoint;
  }
  return `https://developer.worldcoin.org/api/v2/verify/${config.worldIdAppId}`;
}

function worldIdErrorMessage(statusCode: number, rawBody: string): string {
  const fallback = `World ID verify failed (${statusCode})`;
  const body = rawBody.trim();
  if (!body) {
    return fallback;
  }

  try {
    const parsed = JSON.parse(body) as WorldIdVerifyError;
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

export async function verifyWorldIdProof(userAddress: string, proof: WorldIdProof): Promise<void> {
  if (!config.worldIdAppId || !config.worldIdAction) {
    throw new Error("World ID is not configured in CRE env");
  }

  const normalizedAddress = ethers.getAddress(userAddress);
  const signal = normalizedAddress.toLowerCase();
  const verifyResponse = await fetch(worldIdVerifyEndpoint(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ...proof,
      action: config.worldIdAction,
      signal_hash: hashSignalToField(signal)
    })
  });

  if (!verifyResponse.ok) {
    const errorBody = await verifyResponse.text();
    throw new Error(worldIdErrorMessage(verifyResponse.status, errorBody));
  }
}

export async function attestWorldIdFlag(
  userAddress: string,
  proof: WorldIdProof
): Promise<{ alreadyVerified: boolean; flags: string; txHash?: string }> {
  const normalizedAddress = ethers.getAddress(userAddress);
  await verifyWorldIdProof(normalizedAddress, proof);

  const registry = getRegistry();
  const current = await registry.attestations(normalizedAddress);
  const currentFlags = BigInt(current[0]);
  const currentExpiration = Number(current[1]);
  const currentRiskScore = Number(current[2]);
  const currentSubjectType = Number(current[3]);
  const currentRevoked = Boolean(current[6]);
  const currentExists = Boolean(current[7]);

  if (currentRevoked) {
    throw new Error("Attestation is revoked. Cannot attach World ID flag until record is restored.");
  }

  const nextFlags = currentFlags | config.flagWorldId;
  if (currentExists && nextFlags === currentFlags) {
    return { alreadyVerified: true, flags: nextFlags.toString() };
  }

  const now = Math.floor(Date.now() / 1000);
  const fallbackExpiration = now + config.attestationExpirationDays * 24 * 60 * 60;
  const nextExpiration = currentExpiration > now ? currentExpiration : fallbackExpiration;
  const nextRiskScore = currentExists ? currentRiskScore : 0;
  const nextSubjectType = currentExists && currentSubjectType > 0 ? currentSubjectType : 1;
  const refHash = ethers.keccak256(
    ethers.toUtf8Bytes(`worldid:${normalizedAddress.toLowerCase()}:${proof.nullifier_hash}:${Date.now()}`)
  );

  const tx = await registry.attest(normalizedAddress, {
    flags: nextFlags,
    expiration: BigInt(nextExpiration),
    riskScore: nextRiskScore,
    subjectType: nextSubjectType,
    refHash
  });
  await tx.wait();

  return {
    alreadyVerified: false,
    flags: nextFlags.toString(),
    txHash: tx.hash
  };
}

