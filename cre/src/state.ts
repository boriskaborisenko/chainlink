import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { config } from "./config.js";
import { WorkflowState } from "./types.js";

const DEFAULT_STATE: WorkflowState = {
  lastIssueTokenBlock: 0,
  lastSyncBlock: 0,
  users: {},
  sumsubUserIds: {}
};

function statePath() {
  return resolve(process.cwd(), config.stateFile);
}

export function readState(): WorkflowState {
  const path = statePath();

  if (!existsSync(path)) {
    return DEFAULT_STATE;
  }

  const raw = readFileSync(path, "utf8");

  try {
    const parsed = JSON.parse(raw) as WorkflowState;
    return {
      lastIssueTokenBlock: parsed.lastIssueTokenBlock ?? 0,
      lastSyncBlock: parsed.lastSyncBlock ?? 0,
      users: parsed.users ?? {},
      sumsubUserIds: parsed.sumsubUserIds ?? {}
    };
  } catch {
    return DEFAULT_STATE;
  }
}

export function writeState(state: WorkflowState): void {
  const path = statePath();
  writeFileSync(path, JSON.stringify(state, null, 2));
}
