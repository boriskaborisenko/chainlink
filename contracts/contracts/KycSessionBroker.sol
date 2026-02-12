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

    mapping(address => bool) public isIssuer;
    mapping(address => bytes) public encryptionPubKey;
    mapping(uint256 => TokenPacket) private packets;

    event IssuerSet(address indexed issuer, bool allowed);
    event EncryptionPubKeySet(address indexed user, bytes pubKey);
    event KycRequested(uint256 indexed requestId, address indexed user, string levelName);
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

    function requestKyc(string calldata levelName) external returns (uint256 requestId) {
        require(encryptionPubKey[msg.sender].length > 0, "KycSessionBroker: missing pub key");

        requestId = nextRequestId;
        nextRequestId = requestId + 1;

        TokenPacket storage packet = packets[requestId];
        packet.user = msg.sender;
        packet.exists = true;

        emit KycRequested(requestId, msg.sender, levelName);
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
