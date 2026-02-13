export type ReviewDecision = "GREEN" | "RED" | "PENDING";

export interface KycRequestEventData {
  requestId: bigint;
  user: string;
  levelName: string;
  blockNumber: number;
}

export interface KycSyncRequestEventData {
  syncRequestId: bigint;
  user: string;
  requestId: bigint;
  blockNumber: number;
}

export interface SumsubTokenResponse {
  token: string;
  userId: string;
  levelName: string;
  ttlInSecs: number;
  raw: unknown;
}

export interface SumsubReviewStatus {
  userId: string;
  applicantId?: string;
  decision: ReviewDecision;
  raw: unknown;
}

export interface UserSyncState {
  userId?: string;
  lastSeenRequestId?: string;
  lastReviewDecision?: ReviewDecision;
  lastSyncAt?: string;
}

export interface WorkflowState {
  lastIssueTokenBlock: number;
  lastSyncBlock: number;
  users: Record<string, UserSyncState>;
}
