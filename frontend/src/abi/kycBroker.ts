export const kycBrokerAbi = [
  "event KycRequested(uint256 indexed requestId, address indexed user, string levelName)",
  "function setEncryptionPubKey(bytes pubKey)",
  "function encryptionPubKey(address user) view returns (bytes)",
  "function requestKyc(string levelName) returns (uint256 requestId)",
  "function getPacket(uint256 requestId) view returns (address user, bytes ciphertext, uint64 expiresAt, bool consumed, bool exists)",
  "function markConsumed(uint256 requestId)"
] as const;
