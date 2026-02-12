export const passRegistryAbi = [
  "function verifyUser(address user, uint256 policyId) view returns (bool ok, uint8 reason)",
  "function attestations(address user) view returns (uint256 flags, uint64 expiration, uint32 riskScore, uint8 subjectType, bytes32 refHash, uint64 updatedAt, bool revoked, bool exists)",
  "function isIssuer(address issuer) view returns (bool)",
  "function FLAG_HUMAN() view returns (uint256)"
] as const;
