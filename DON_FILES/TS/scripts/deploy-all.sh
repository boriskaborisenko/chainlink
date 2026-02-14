#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-production-settings}"

echo "Target: $TARGET"

echo "==> Deploy IssueSdkToken"
cre workflow deploy ./workflows/issue-sdk-token --target "$TARGET"
cre workflow activate ./workflows/issue-sdk-token --target "$TARGET"

echo "==> Deploy SyncKycStatus"
cre workflow deploy ./workflows/sync-kyc-status --target "$TARGET"
cre workflow activate ./workflows/sync-kyc-status --target "$TARGET"

echo "Done"
