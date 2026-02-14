#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-staging-settings}"

echo "Target: $TARGET"

echo "==> Simulate IssueSdkToken"
cre workflow simulate ./workflows/issue-sdk-token --target "$TARGET"

echo "==> Simulate SyncKycStatus"
cre workflow simulate ./workflows/sync-kyc-status --target "$TARGET"

echo "Done"
