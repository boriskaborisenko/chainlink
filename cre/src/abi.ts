export const BROKER_ABI = [
  "event KycRequested(uint256 indexed requestId, address indexed user, string levelName)",
  "function encryptionPubKey(address user) view returns (bytes)",
  "function getPacket(uint256 requestId) view returns (address user, bytes ciphertext, uint64 expiresAt, bool consumed, bool exists)",
  "function storeEncryptedToken(uint256 requestId, bytes ciphertext, uint64 expiresAt)"
] as const;

export const REGISTRY_ABI = [
  "function attest(address user, (uint256 flags, uint64 expiration, uint32 riskScore, uint8 subjectType, bytes32 refHash) data)",
  "function revoke(address user)",
  "function attestations(address user) view returns (uint256 flags, uint64 expiration, uint32 riskScore, uint8 subjectType, bytes32 refHash, uint64 updatedAt, bool revoked, bool exists)"
] as const;
