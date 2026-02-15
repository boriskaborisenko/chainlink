export const kycBrokerAbi = [
  "event KycRequested(uint256 indexed requestId, address indexed user, string levelName)",
  "event KycSyncRequested(uint256 indexed syncRequestId, address indexed user, uint256 indexed requestId)",
  "event WorldIdVerificationRequested(uint256 indexed worldIdRequestId, address indexed user, string nullifierHash, string verificationLevel)",
  "function setEncryptionPubKey(bytes pubKey)",
  "function encryptionPubKey(address user) view returns (bytes)",
  "function requestKyc(string levelName) returns (uint256 requestId)",
  "function requestKycSync() returns (uint256 syncRequestId)",
  "function requestWorldIdVerification(string proof, string merkleRoot, string nullifierHash, string verificationLevel) returns (uint256 worldIdRequestId)",
  "function getPacket(uint256 requestId) view returns (address user, bytes ciphertext, uint64 expiresAt, bool consumed, bool exists)",
  "function markConsumed(uint256 requestId)"
] as const;
