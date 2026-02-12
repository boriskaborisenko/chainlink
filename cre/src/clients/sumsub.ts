import { createHmac } from "node:crypto";
import { config } from "../config.js";
import { ReviewDecision, SumsubReviewStatus, SumsubTokenResponse } from "../types.js";

function signature(ts: string, method: string, path: string, body: string): string {
  const payload = `${ts}${method.toUpperCase()}${path}${body}`;
  return createHmac("sha256", config.sumsubSecretKey).update(payload).digest("hex");
}

async function requestSumsub(method: string, path: string, body?: unknown): Promise<unknown> {
  const ts = Math.floor(Date.now() / 1000).toString();
  const bodyString = body ? JSON.stringify(body) : "";

  const headers: Record<string, string> = {
    "X-App-Token": config.sumsubAppToken,
    "X-App-Access-Ts": ts,
    "X-App-Access-Sig": signature(ts, method, path, bodyString)
  };

  if (body) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${config.sumsubBaseUrl}${path}`, {
    method,
    headers,
    body: body ? bodyString : undefined
  });

  if (!res.ok) {
    const errText = await res.text();
    let hint = "";

    try {
      const parsed = JSON.parse(errText) as {
        errorName?: string;
        errorCode?: number;
        description?: string;
      };

      if (parsed.errorName === "app-token-invalid-format" || parsed.errorCode === 4000) {
        hint =
          " | Hint: SUMSUB_APP_TOKEN must be your Sumsub App Token (not SDK access token), copied without quotes/spaces.";
      } else if (parsed.errorCode === 4002) {
        hint =
          " | Hint: APP token and SECRET key do not match. Use both from the same Sumsub app/environment.";
      }
    } catch {
      // Keep raw text only.
    }

    throw new Error(`Sumsub ${method} ${path} failed (${res.status}): ${errText}${hint}`);
  }

  return res.json();
}

function normalizeReviewDecision(rawStatus?: string): ReviewDecision {
  const normalized = (rawStatus ?? "").toUpperCase();

  if (normalized.includes("GREEN") || normalized.includes("APPROVED") || normalized.includes("COMPLETED")) {
    return "GREEN";
  }

  if (normalized.includes("RED") || normalized.includes("REJECTED") || normalized.includes("DECLINED")) {
    return "RED";
  }

  return "PENDING";
}

export async function generateSdkToken(
  userId: string,
  levelName: string,
  ttlInSecs: number
): Promise<SumsubTokenResponse> {
  const body = {
    userId,
    levelName,
    ttlInSecs
  };

  const raw = (await requestSumsub("POST", config.sumsubSdkTokenPath, body)) as Record<string, unknown>;

  const token = typeof raw.token === "string" ? raw.token : "";
  if (!token) {
    throw new Error(`Sumsub token response did not include token field: ${JSON.stringify(raw)}`);
  }

  return {
    token,
    userId,
    levelName,
    ttlInSecs,
    raw
  };
}

export async function getReviewStatusByUserId(userId: string): Promise<SumsubReviewStatus> {
  const path = config.sumsubStatusPathTemplate.replace("{userId}", encodeURIComponent(userId));
  const raw = (await requestSumsub("GET", path)) as Record<string, any>;

  const reviewStatus =
    raw?.review?.reviewStatus ?? raw?.reviewStatus ?? raw?.reviewResult?.reviewAnswer ?? raw?.inspectionStatus;

  const decision = normalizeReviewDecision(reviewStatus);

  return {
    userId,
    applicantId: raw?.id ?? raw?.applicantId,
    decision,
    raw
  };
}
