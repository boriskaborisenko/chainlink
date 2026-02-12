package eth

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"passstore/cre_go/internal/config"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type KycRequestedEvent struct {
	RequestID   *big.Int
	User        common.Address
	LevelName   string
	BlockNumber uint64
}

type Packet struct {
	User       common.Address
	Ciphertext []byte
	ExpiresAt  uint64
	Consumed   bool
	Exists     bool
}

type AttestationData struct {
	Flags       *big.Int `abi:"flags"`
	Expiration  uint64   `abi:"expiration"`
	RiskScore   uint32   `abi:"riskScore"`
	SubjectType uint8    `abi:"subjectType"`
	RefHash     [32]byte `abi:"refHash"`
}

type Clients struct {
	RPC          *ethclient.Client
	ChainID      *big.Int
	Signer       *bind.TransactOpts
	BrokerAddr   common.Address
	RegistryAddr common.Address
	BrokerABI    abi.ABI
	RegistryABI  abi.ABI
	broker       *bind.BoundContract
	registry     *bind.BoundContract
}

func New(cfg config.Config) (*Clients, error) {
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc: %w", err)
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("chain id: %w", err)
	}

	pkHex := strings.TrimPrefix(cfg.CRESignerPK, "0x")
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, fmt.Errorf("decode CRE_SIGNER_PK: %w", err)
	}

	pk, err := crypto.ToECDSA(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("parse CRE_SIGNER_PK: %w", err)
	}

	txSigner, err := bind.NewKeyedTransactorWithChainID(pk, chainID)
	if err != nil {
		return nil, fmt.Errorf("transactor: %w", err)
	}

	brokerAddr := common.HexToAddress(cfg.BrokerAddress)
	registryAddr := common.HexToAddress(cfg.RegistryAddress)
	brokerABI := MustBrokerABI()
	registryABI := MustRegistryABI()

	c := &Clients{
		RPC:          client,
		ChainID:      chainID,
		Signer:       txSigner,
		BrokerAddr:   brokerAddr,
		RegistryAddr: registryAddr,
		BrokerABI:    brokerABI,
		RegistryABI:  registryABI,
		broker:       bind.NewBoundContract(brokerAddr, brokerABI, client, client, client),
		registry:     bind.NewBoundContract(registryAddr, registryABI, client, client, client),
	}

	return c, nil
}

func (c *Clients) txOpts(ctx context.Context) *bind.TransactOpts {
	clone := *c.Signer
	clone.Context = ctx
	return &clone
}

func (c *Clients) LatestBlock(ctx context.Context) (uint64, error) {
	return c.RPC.BlockNumber(ctx)
}

func (c *Clients) QueryKycRequested(ctx context.Context, fromBlock, toBlock uint64) ([]KycRequestedEvent, error) {
	if fromBlock > toBlock {
		return []KycRequestedEvent{}, nil
	}

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(fromBlock),
		ToBlock:   new(big.Int).SetUint64(toBlock),
		Addresses: []common.Address{c.BrokerAddr},
		Topics:    [][]common.Hash{{BrokerKycRequestedTopic()}},
	}

	logs, err := c.RPC.FilterLogs(ctx, query)
	if err != nil {
		return nil, err
	}

	events := make([]KycRequestedEvent, 0, len(logs))
	for _, lg := range logs {
		if len(lg.Topics) < 3 {
			continue
		}

		vals, err := c.BrokerABI.Unpack("KycRequested", lg.Data)
		if err != nil || len(vals) < 1 {
			continue
		}

		levelName, _ := vals[0].(string)
		requestID := new(big.Int).SetBytes(lg.Topics[1].Bytes())
		user := common.BytesToAddress(lg.Topics[2].Bytes()[12:])

		events = append(events, KycRequestedEvent{
			RequestID:   requestID,
			User:        user,
			LevelName:   levelName,
			BlockNumber: lg.BlockNumber,
		})
	}

	return events, nil
}

func (c *Clients) EncryptionPubKey(ctx context.Context, user common.Address) ([]byte, error) {
	var out []interface{}
	err := c.broker.Call(&bind.CallOpts{Context: ctx}, &out, "encryptionPubKey", user)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	b, _ := out[0].([]byte)
	return b, nil
}

func (c *Clients) GetPacket(ctx context.Context, requestID *big.Int) (Packet, error) {
	var out []interface{}
	err := c.broker.Call(&bind.CallOpts{Context: ctx}, &out, "getPacket", requestID)
	if err != nil {
		return Packet{}, err
	}
	if len(out) < 5 {
		return Packet{}, fmt.Errorf("unexpected getPacket output length: %d", len(out))
	}

	pkt := Packet{}
	if addr, ok := out[0].(common.Address); ok {
		pkt.User = addr
	}
	if b, ok := out[1].([]byte); ok {
		pkt.Ciphertext = b
	}
	pkt.ExpiresAt = asUint64(out[2])
	if v, ok := out[3].(bool); ok {
		pkt.Consumed = v
	}
	if v, ok := out[4].(bool); ok {
		pkt.Exists = v
	}

	return pkt, nil
}

func (c *Clients) StoreEncryptedToken(ctx context.Context, requestID *big.Int, ciphertext []byte, expiresAt uint64) (*types.Transaction, error) {
	return c.broker.Transact(c.txOpts(ctx), "storeEncryptedToken", requestID, ciphertext, expiresAt)
}

func (c *Clients) AttestationExists(ctx context.Context, user common.Address) (bool, error) {
	var out []interface{}
	err := c.registry.Call(&bind.CallOpts{Context: ctx}, &out, "attestations", user)
	if err != nil {
		return false, err
	}
	if len(out) < 8 {
		return false, fmt.Errorf("unexpected attestations output length: %d", len(out))
	}
	v, _ := out[7].(bool)
	return v, nil
}

func (c *Clients) Attest(ctx context.Context, user common.Address, data AttestationData) (*types.Transaction, error) {
	return c.registry.Transact(c.txOpts(ctx), "attest", user, data)
}

func (c *Clients) Revoke(ctx context.Context, user common.Address) (*types.Transaction, error) {
	return c.registry.Transact(c.txOpts(ctx), "revoke", user)
}

func (c *Clients) WaitMined(ctx context.Context, tx *types.Transaction) error {
	_, err := bind.WaitMined(ctx, c.RPC, tx)
	return err
}

func asUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case uint32:
		return uint64(n)
	case *big.Int:
		return n.Uint64()
	default:
		return 0
	}
}
