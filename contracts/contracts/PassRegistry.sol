// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PassRegistry {
    uint256 public constant FLAG_HUMAN = 1 << 0;

    uint8 public constant REASON_OK = 0;
    uint8 public constant REASON_NO_ATTESTATION = 1;
    uint8 public constant REASON_REVOKED = 2;
    uint8 public constant REASON_EXPIRED = 3;
    uint8 public constant REASON_FLAGS_MISSING = 4;
    uint8 public constant REASON_RISK_TOO_HIGH = 5;
    uint8 public constant REASON_SUBJECT_TYPE_MISMATCH = 6;
    uint8 public constant REASON_POLICY_DISABLED = 7;

    struct Attestation {
        uint256 flags;
        uint64 expiration;
        uint32 riskScore;
        uint8 subjectType;
        bytes32 refHash;
        uint64 updatedAt;
        bool revoked;
        bool exists;
    }

    struct AttestationData {
        uint256 flags;
        uint64 expiration;
        uint32 riskScore;
        uint8 subjectType;
        bytes32 refHash;
    }

    struct Policy {
        uint256 requiredFlags;
        uint32 maxRiskScore;
        uint8 allowedSubjectType; // 0 = any
        bool requireUnexpired;
        bool enabled;
    }

    address public admin;
    uint256 public nextPolicyId;

    mapping(address => Attestation) public attestations;
    mapping(uint256 => Policy) public policies;
    mapping(address => bool) public isIssuer;

    event IssuerSet(address indexed issuer, bool allowed);
    event Attested(
        address indexed user,
        uint256 flags,
        uint64 expiration,
        uint32 riskScore,
        uint8 subjectType,
        bytes32 refHash,
        address indexed issuer
    );
    event Revoked(address indexed user, address indexed issuer);
    event PolicyCreated(
        uint256 indexed policyId,
        uint256 requiredFlags,
        uint32 maxRiskScore,
        uint8 allowedSubjectType,
        bool requireUnexpired,
        bool enabled
    );
    event PolicyUpdated(
        uint256 indexed policyId,
        uint256 requiredFlags,
        uint32 maxRiskScore,
        uint8 allowedSubjectType,
        bool requireUnexpired,
        bool enabled
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "PassRegistry: not admin");
        _;
    }

    modifier onlyIssuer() {
        require(isIssuer[msg.sender], "PassRegistry: not issuer");
        _;
    }

    modifier onlyIssuerOrAdmin() {
        require(msg.sender == admin || isIssuer[msg.sender], "PassRegistry: forbidden");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setIssuer(address issuer, bool allowed) external onlyAdmin {
        isIssuer[issuer] = allowed;
        emit IssuerSet(issuer, allowed);
    }

    function createPolicy(
        uint256 requiredFlags,
        uint32 maxRiskScore,
        uint8 allowedSubjectType,
        bool requireUnexpired,
        bool enabled
    ) external onlyAdmin returns (uint256 policyId) {
        policyId = nextPolicyId;
        nextPolicyId = policyId + 1;

        policies[policyId] = Policy({
            requiredFlags: requiredFlags,
            maxRiskScore: maxRiskScore,
            allowedSubjectType: allowedSubjectType,
            requireUnexpired: requireUnexpired,
            enabled: enabled
        });

        emit PolicyCreated(
            policyId,
            requiredFlags,
            maxRiskScore,
            allowedSubjectType,
            requireUnexpired,
            enabled
        );
    }

    function updatePolicy(
        uint256 policyId,
        uint256 requiredFlags,
        uint32 maxRiskScore,
        uint8 allowedSubjectType,
        bool requireUnexpired,
        bool enabled
    ) external onlyAdmin {
        require(policyId < nextPolicyId, "PassRegistry: policy missing");

        policies[policyId] = Policy({
            requiredFlags: requiredFlags,
            maxRiskScore: maxRiskScore,
            allowedSubjectType: allowedSubjectType,
            requireUnexpired: requireUnexpired,
            enabled: enabled
        });

        emit PolicyUpdated(
            policyId,
            requiredFlags,
            maxRiskScore,
            allowedSubjectType,
            requireUnexpired,
            enabled
        );
    }

    function attest(address user, AttestationData calldata data) external onlyIssuer {
        attestations[user] = Attestation({
            flags: data.flags,
            expiration: data.expiration,
            riskScore: data.riskScore,
            subjectType: data.subjectType,
            refHash: data.refHash,
            updatedAt: uint64(block.timestamp),
            revoked: false,
            exists: true
        });

        emit Attested(
            user,
            data.flags,
            data.expiration,
            data.riskScore,
            data.subjectType,
            data.refHash,
            msg.sender
        );
    }

    function revoke(address user) external onlyIssuerOrAdmin {
        Attestation storage current = attestations[user];
        require(current.exists, "PassRegistry: no attestation");

        current.revoked = true;
        current.updatedAt = uint64(block.timestamp);

        emit Revoked(user, msg.sender);
    }

    function verifyUser(address user, uint256 policyId) external view returns (bool ok, uint8 reason) {
        Policy memory policy = policies[policyId];
        if (!policy.enabled) {
            return (false, REASON_POLICY_DISABLED);
        }

        Attestation memory a = attestations[user];
        if (!a.exists) {
            return (false, REASON_NO_ATTESTATION);
        }

        if (a.revoked) {
            return (false, REASON_REVOKED);
        }

        if (policy.requireUnexpired && (a.expiration == 0 || a.expiration < block.timestamp)) {
            return (false, REASON_EXPIRED);
        }

        if ((a.flags & policy.requiredFlags) != policy.requiredFlags) {
            return (false, REASON_FLAGS_MISSING);
        }

        if (policy.maxRiskScore > 0 && a.riskScore > policy.maxRiskScore) {
            return (false, REASON_RISK_TOO_HIGH);
        }

        if (policy.allowedSubjectType != 0 && a.subjectType != policy.allowedSubjectType) {
            return (false, REASON_SUBJECT_TYPE_MISMATCH);
        }

        return (true, REASON_OK);
    }
}
