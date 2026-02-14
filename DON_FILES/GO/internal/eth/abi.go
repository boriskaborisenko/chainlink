package eth

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const brokerABIJSON = `[
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"requestId","type":"uint256"},{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":false,"internalType":"string","name":"levelName","type":"string"}],"name":"KycRequested","type":"event"},
  {"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"encryptionPubKey","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"requestId","type":"uint256"}],"name":"getPacket","outputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"bytes","name":"ciphertext","type":"bytes"},{"internalType":"uint64","name":"expiresAt","type":"uint64"},{"internalType":"bool","name":"consumed","type":"bool"},{"internalType":"bool","name":"exists","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"requestId","type":"uint256"},{"internalType":"bytes","name":"ciphertext","type":"bytes"},{"internalType":"uint64","name":"expiresAt","type":"uint64"}],"name":"storeEncryptedToken","outputs":[],"stateMutability":"nonpayable","type":"function"}
]`

const registryABIJSON = `[
  {"inputs":[{"internalType":"address","name":"user","type":"address"},{"components":[{"internalType":"uint256","name":"flags","type":"uint256"},{"internalType":"uint64","name":"expiration","type":"uint64"},{"internalType":"uint32","name":"riskScore","type":"uint32"},{"internalType":"uint8","name":"subjectType","type":"uint8"},{"internalType":"bytes32","name":"refHash","type":"bytes32"}],"internalType":"struct PassRegistry.AttestationData","name":"data","type":"tuple"}],"name":"attest","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"revoke","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"attestations","outputs":[{"internalType":"uint256","name":"flags","type":"uint256"},{"internalType":"uint64","name":"expiration","type":"uint64"},{"internalType":"uint32","name":"riskScore","type":"uint32"},{"internalType":"uint8","name":"subjectType","type":"uint8"},{"internalType":"bytes32","name":"refHash","type":"bytes32"},{"internalType":"uint64","name":"updatedAt","type":"uint64"},{"internalType":"bool","name":"revoked","type":"bool"},{"internalType":"bool","name":"exists","type":"bool"}],"stateMutability":"view","type":"function"}
]`

func MustBrokerABI() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(brokerABIJSON))
	if err != nil {
		panic(err)
	}
	return parsed
}

func MustRegistryABI() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(registryABIJSON))
	if err != nil {
		panic(err)
	}
	return parsed
}

func BrokerKycRequestedTopic() common.Hash {
	return MustBrokerABI().Events["KycRequested"].ID
}
