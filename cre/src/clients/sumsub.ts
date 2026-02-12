import { createHmac } from "node:crypto";
import { config } from "../config.js";
import { ReviewDecision, SumsubReviewStatus, SumsubTokenResponse } from "../types.js";

type SumsubErrorPayload = {
  errorName?: string;
  errorCode?: number;
  description?: string;
};

class SumsubHttpError extends Error {
  readonly status: number;
  readonly method: string;
  readonly path: string;
  readonly bodyText: string;
  readonly payload?: SumsubErrorPayload;

  constructor(
    method: string,
    path: string,
    status: number,
    bodyText: string,
    payload?: SumsubErrorPayload,
    hint?: string
  ) {
    super(`Sumsub ${method} ${path} failed (${status}): ${bodyText}${hint ?? ""}`);
    this.name = "SumsubHttpError";
    this.status = status;
    this.method = method;
    this.path = path;
    this.bodyText = bodyText;
    this.payload = payload;
  }
}

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
    let payload: SumsubErrorPayload | undefined;
    let hint = "";

    try {
      const parsed = JSON.parse(errText) as SumsubErrorPayload;
      payload = parsed;

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

    throw new SumsubHttpError(method, path, res.status, errText, payload, hint);
  }

  return res.json();
}

function isApplicantNotFoundError(err: unknown): boolean {
  if (!(err instanceof SumsubHttpError) || err.status !== 404) {
    return false;
  }

  const description = err.payload?.description?.toLowerCase() ?? "";
  return description.includes("applicant not found");
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
  let raw: Record<string, any>;

  try {
    raw = (await requestSumsub("GET", path)) as Record<string, any>;
  } catch (err) {
    if (isApplicantNotFoundError(err)) {
      return {
        userId,
        decision: "PENDING",
        raw: { applicantNotFound: true }
      };
    }

    throw err;
  }

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
