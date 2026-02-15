package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"passstore/don_files_go/internal/config"
	"passstore/don_files_go/internal/cryptobox"
	"passstore/don_files_go/internal/eth"
	"passstore/don_files_go/internal/state"
	"passstore/don_files_go/internal/sumsub"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	loop := flag.Bool("loop", false, "run worker continuously")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	chain, err := eth.New(cfg)
	if err != nil {
		log.Fatalf("eth client: %v", err)
	}
	sumClient := sumsub.New(cfg)

	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		if err := runOnce(ctx, cfg, chain, sumClient); err != nil {
			log.Printf("Unified worker run error: %v", err)
		}
	}

	if !*loop {
		run()
		return
	}

	log.Printf("Unified GO worker started with issueInterval=%dms syncInterval=%dms", cfg.PollIntervalMS, cfg.SyncPollIntervalMS)
	lastSyncAt := time.Time{}

	for {
		loopStartedAt := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

		latest, err := chain.LatestBlock(ctx)
		if err != nil {
			log.Printf("Unified worker run error: latest block: %v", err)
			cancel()
		} else {
			if err := runIssuePass(ctx, cfg, chain, sumClient, latest, nil); err != nil {
				log.Printf("issue pass error: %v", err)
			}

			now := time.Now()
			if lastSyncAt.IsZero() || now.Sub(lastSyncAt) >= time.Duration(cfg.SyncPollIntervalMS)*time.Millisecond {
				if err := runSyncPass(ctx, cfg, chain, sumClient, latest, nil); err != nil {
					log.Printf("sync pass error: %v", err)
				} else {
					lastSyncAt = time.Now()
				}
			}
			cancel()
		}

		elapsed := time.Since(loopStartedAt)
		sleepFor := time.Duration(cfg.PollIntervalMS)*time.Millisecond - elapsed
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		}
	}
}

func runOnce(ctx context.Context, cfg config.Config, chain *eth.Clients, sumClient *sumsub.Client) error {
	st, err := state.Read(cfg.StateFile)
	if err != nil {
		return err
	}

	latest, err := chain.LatestBlock(ctx)
	if err != nil {
		return err
	}

	if err := runIssuePass(ctx, cfg, chain, sumClient, latest, &st); err != nil {
		log.Printf("issue pass error: %v", err)
	}

	if err := runSyncPass(ctx, cfg, chain, sumClient, latest, &st); err != nil {
		log.Printf("sync pass error: %v", err)
	}

	return state.Write(cfg.StateFile, st)
}

func readStateForPass(cfg config.Config, st *state.WorkflowState) (state.WorkflowState, error) {
	if st != nil {
		return *st, nil
	}
	return state.Read(cfg.StateFile)
}

func writeStateForPass(cfg config.Config, next state.WorkflowState, st *state.WorkflowState) error {
	if st != nil {
		*st = next
		return nil
	}
	return state.Write(cfg.StateFile, next)
}

func runIssuePass(
	ctx context.Context,
	cfg config.Config,
	chain *eth.Clients,
	sumClient *sumsub.Client,
	latest uint64,
	st *state.WorkflowState,
) error {
	currentState, err := readStateForPass(cfg, st)
	if err != nil {
		return err
	}

	fromBlock := uint64(0)
	if currentState.LastIssueTokenBlock > 0 {
		fromBlock = currentState.LastIssueTokenBlock + 1
	} else if latest > 2000 {
		fromBlock = latest - 2000
	}

	if fromBlock > latest {
		currentState.LastIssueTokenBlock = latest
		return writeStateForPass(cfg, currentState, st)
	}

	events, err := chain.QueryKycRequested(ctx, fromBlock, latest)
	if err != nil {
		return err
	}

	for _, ev := range events {
		if err := processIssueEvent(ctx, cfg, chain, sumClient, ev, &currentState); err != nil {
			log.Printf("issue event requestId=%s failed: %v", ev.RequestID.String(), err)
		}
	}

	currentState.LastIssueTokenBlock = latest
	return writeStateForPass(cfg, currentState, st)
}

func processIssueEvent(
	ctx context.Context,
	cfg config.Config,
	chain *eth.Clients,
	sumClient *sumsub.Client,
	ev eth.KycRequestedEvent,
	st *state.WorkflowState,
) error {
	pkt, err := chain.GetPacket(ctx, ev.RequestID)
	if err != nil {
		return err
	}
	if len(pkt.Ciphertext) > 0 {
		log.Printf("requestId=%s already has token packet, skipping", ev.RequestID.String())
		return nil
	}

	pubKeyBytes, err := chain.EncryptionPubKey(ctx, ev.User)
	if err != nil {
		return err
	}
	if len(pubKeyBytes) == 0 {
		log.Printf("user=%s has no encryption key, skipping requestId=%s", ev.User.Hex(), ev.RequestID.String())
		return nil
	}
	if len(pubKeyBytes) != 32 {
		log.Printf(
			"user=%s has invalid encryption key length=%d, skipping requestId=%s",
			ev.User.Hex(),
			len(pubKeyBytes),
			ev.RequestID.String(),
		)
		return nil
	}

	if ev.LevelName != "" && ev.LevelName != cfg.KYCLevelName {
		log.Printf("requestId=%s event level '%s' overridden by ENV level '%s'", ev.RequestID.String(), ev.LevelName, cfg.KYCLevelName)
	}

	token, err := sumClient.GenerateSDKToken(ctx, ev.User.Hex(), cfg.KYCLevelName, cfg.TokenTTLSeconds)
	if err != nil {
		return err
	}

	ciphertext, err := cryptobox.EncryptForSessionKey(pubKeyBytes, token)
	if err != nil {
		return err
	}

	expiresAt := uint64(time.Now().Unix()) + uint64(cfg.TokenTTLSeconds)
	tx, err := chain.StoreEncryptedToken(ctx, ev.RequestID, ciphertext, expiresAt)
	if err != nil {
		return err
	}
	if err := chain.WaitMined(ctx, tx); err != nil {
		return err
	}

	log.Printf("stored encrypted token requestId=%s user=%s tx=%s", ev.RequestID.String(), ev.User.Hex(), tx.Hash().Hex())

	key := strings.ToLower(ev.User.Hex())
	u := st.Users[key]
	u.UserID = ev.User.Hex()
	u.LastSeenRequestID = ev.RequestID.String()
	st.Users[key] = u

	return nil
}

func runSyncPass(
	ctx context.Context,
	cfg config.Config,
	chain *eth.Clients,
	sumClient *sumsub.Client,
	latest uint64,
	st *state.WorkflowState,
) error {
	currentState, err := readStateForPass(cfg, st)
	if err != nil {
		return err
	}

	fromBlock := uint64(0)
	if currentState.LastSyncBlock > 0 {
		fromBlock = currentState.LastSyncBlock + 1
	} else if latest > 2000 {
		fromBlock = latest - 2000
	}

	if fromBlock <= latest {
		recentRequests, err := chain.QueryKycRequested(ctx, fromBlock, latest)
		if err != nil {
			return err
		}

		for _, ev := range recentRequests {
			key := strings.ToLower(ev.User.Hex())
			u := currentState.Users[key]
			u.UserID = ev.User.Hex()
			u.LastSeenRequestID = ev.RequestID.String()
			currentState.Users[key] = u
		}
	}

	if len(currentState.Users) == 0 {
		log.Printf("Sync pass: no users to check yet")
	}

	for key, userState := range currentState.Users {
		userID := userState.UserID
		if userID == "" {
			userID = key
		}

		decision, err := sumClient.GetReviewDecisionByUserID(ctx, userID)
		if err != nil {
			log.Printf("failed to sync user=%s: %v", userID, err)
			continue
		}

		if state.ReviewDecision(decision) != userState.LastReviewDecision {
			if err := applyDecision(ctx, cfg, chain, userID, decision); err != nil {
				log.Printf("apply decision failed user=%s: %v", userID, err)
				continue
			}
		} else if decision != sumsub.DecisionPending {
			log.Printf("user=%s status unchanged (%s)", userID, decision)
		}

		u := currentState.Users[key]
		u.UserID = userID
		u.LastReviewDecision = state.ReviewDecision(decision)
		u = state.TouchSyncTime(u)
		currentState.Users[key] = u
	}

	currentState.LastSyncBlock = latest
	return writeStateForPass(cfg, currentState, st)
}

func applyDecision(ctx context.Context, cfg config.Config, chain *eth.Clients, userID string, decision sumsub.ReviewDecision) error {
	user := common.HexToAddress(userID)

	switch decision {
	case sumsub.DecisionGreen:
		return upsertAttestation(ctx, cfg, chain, user)
	case sumsub.DecisionRed:
		return revokeAttestation(ctx, chain, user)
	default:
		log.Printf("user=%s still pending", userID)
		return nil
	}
}

func upsertAttestation(ctx context.Context, cfg config.Config, chain *eth.Clients, user common.Address) error {
	expiresAt := uint64(time.Now().AddDate(0, 0, cfg.AttestationExpiryDays).Unix())
	ref := crypto.Keccak256Hash([]byte(fmt.Sprintf("%s:%d", user.Hex(), time.Now().UnixNano())))

	var refHash [32]byte
	copy(refHash[:], ref.Bytes())

	data := eth.AttestationData{
		Flags:       new(big.Int).SetUint64(cfg.FlagHuman),
		Expiration:  expiresAt,
		RiskScore:   0,
		SubjectType: 1,
		RefHash:     refHash,
	}

	tx, err := chain.Attest(ctx, user, data)
	if err != nil {
		return err
	}
	if err := chain.WaitMined(ctx, tx); err != nil {
		return err
	}

	log.Printf("attested user=%s tx=%s", user.Hex(), tx.Hash().Hex())
	return nil
}

func revokeAttestation(ctx context.Context, chain *eth.Clients, user common.Address) error {
	exists, err := chain.AttestationExists(ctx, user)
	if err != nil {
		return err
	}
	if !exists {
		log.Printf("user=%s has no attestation yet; skip revoke", user.Hex())
		return nil
	}

	tx, err := chain.Revoke(ctx, user)
	if err != nil {
		return err
	}
	if err := chain.WaitMined(ctx, tx); err != nil {
		return err
	}

	log.Printf("revoked user=%s tx=%s", user.Hex(), tx.Hash().Hex())
	return nil
}
