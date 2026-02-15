export const BROKER_ABI = [
  "event KycRequested(uint256 indexed requestId, address indexed user, string levelName)",
  "event KycSyncRequested(uint256 indexed syncRequestId, address indexed user, uint256 indexed requestId)",
  "event WorldIdVerificationRequested(uint256 indexed worldIdRequestId, address indexed user, string nullifierHash, string verificationLevel)",
  "function encryptionPubKey(address user) view returns (bytes)",
  "function getPacket(uint256 requestId) view returns (address user, bytes ciphertext, uint64 expiresAt, bool consumed, bool exists)",
  "function storeEncryptedToken(uint256 requestId, bytes ciphertext, uint64 expiresAt)",
  "function requestWorldIdVerification(string proof, string merkleRoot, string nullifierHash, string verificationLevel) returns (uint256 worldIdRequestId)"
] as const;

export const REGISTRY_ABI = [
  "function attest(address user, (uint256 flags, uint64 expiration, uint32 riskScore, uint8 subjectType, bytes32 refHash) data)",
  "function revoke(address user)",
  "function attestations(address user) view returns (uint256 flags, uint64 expiration, uint32 riskScore, uint8 subjectType, bytes32 refHash, uint64 updatedAt, bool revoked, bool exists)"
] as const;
