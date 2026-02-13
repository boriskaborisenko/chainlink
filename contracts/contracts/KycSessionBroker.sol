// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract KycSessionBroker {
    struct TokenPacket {
        address user;
        bytes ciphertext;
        uint64 expiresAt;
        bool consumed;
        bool exists;
    }

    address public admin;
    uint256 public nextRequestId;
    uint256 public nextSyncRequestId;
    uint64 public syncCooldown;

    mapping(address => bool) public isIssuer;
    mapping(address => bytes) public encryptionPubKey;
    mapping(address => bool) public hasKycRequest;
    mapping(address => uint256) public latestKycRequestId;
    mapping(address => uint64) public lastSyncRequestAt;
    mapping(uint256 => TokenPacket) private packets;

    event IssuerSet(address indexed issuer, bool allowed);
    event EncryptionPubKeySet(address indexed user, bytes pubKey);
    event KycRequested(uint256 indexed requestId, address indexed user, string levelName);
    event KycSyncRequested(uint256 indexed syncRequestId, address indexed user, uint256 indexed requestId);
    event TokenStored(uint256 indexed requestId, address indexed user, uint64 expiresAt);
    event TokenConsumed(uint256 indexed requestId, address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "KycSessionBroker: not admin");
        _;
    }

    modifier onlyIssuer() {
        require(isIssuer[msg.sender], "KycSessionBroker: not issuer");
        _;
    }

    constructor() {
        admin = msg.sender;
        syncCooldown = 60;
    }

    function setIssuer(address issuer, bool allowed) external onlyAdmin {
        isIssuer[issuer] = allowed;
        emit IssuerSet(issuer, allowed);
    }

    function setEncryptionPubKey(bytes calldata pubKey) external {
        require(pubKey.length > 0, "KycSessionBroker: empty pub key");
        encryptionPubKey[msg.sender] = pubKey;
        emit EncryptionPubKeySet(msg.sender, pubKey);
    }

    function setSyncCooldown(uint64 newCooldown) external onlyAdmin {
        syncCooldown = newCooldown;
    }

    function requestKyc(string calldata levelName) external returns (uint256 requestId) {
        require(encryptionPubKey[msg.sender].length > 0, "KycSessionBroker: missing pub key");

        requestId = nextRequestId;
        nextRequestId = requestId + 1;

        TokenPacket storage packet = packets[requestId];
        packet.user = msg.sender;
        packet.exists = true;

        hasKycRequest[msg.sender] = true;
        latestKycRequestId[msg.sender] = requestId;

        emit KycRequested(requestId, msg.sender, levelName);
    }

    function requestKycSync() external returns (uint256 syncRequestId) {
        require(hasKycRequest[msg.sender], "KycSessionBroker: no kyc request");

        uint64 cooldown = syncCooldown;
        if (cooldown > 0) {
            uint64 availableAt = lastSyncRequestAt[msg.sender] + cooldown;
            require(block.timestamp >= availableAt, "KycSessionBroker: sync cooldown");
        }

        uint256 requestId = latestKycRequestId[msg.sender];

        syncRequestId = nextSyncRequestId;
        nextSyncRequestId = syncRequestId + 1;

        lastSyncRequestAt[msg.sender] = uint64(block.timestamp);
        emit KycSyncRequested(syncRequestId, msg.sender, requestId);
    }

    function storeEncryptedToken(
        uint256 requestId,
        bytes calldata ciphertext,
        uint64 expiresAt
    ) external onlyIssuer {
        TokenPacket storage packet = packets[requestId];
        require(packet.exists, "KycSessionBroker: request missing");
        require(packet.user != address(0), "KycSessionBroker: user missing");

        packet.ciphertext = ciphertext;
        packet.expiresAt = expiresAt;
        packet.consumed = false;

        emit TokenStored(requestId, packet.user, expiresAt);
    }

    function markConsumed(uint256 requestId) external {
        TokenPacket storage packet = packets[requestId];
        require(packet.exists, "KycSessionBroker: request missing");
        require(packet.user == msg.sender, "KycSessionBroker: not packet owner");
        require(!packet.consumed, "KycSessionBroker: already consumed");

        packet.consumed = true;
        emit TokenConsumed(requestId, msg.sender);
    }

    function getPacket(
        uint256 requestId
    ) external view returns (address user, bytes memory ciphertext, uint64 expiresAt, bool consumed, bool exists) {
        TokenPacket memory packet = packets[requestId];
        return (packet.user, packet.ciphertext, packet.expiresAt, packet.consumed, packet.exists);
    }
}
