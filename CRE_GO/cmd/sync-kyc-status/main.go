package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"passstore/cre_go/internal/config"
	"passstore/cre_go/internal/eth"
	"passstore/cre_go/internal/state"
	"passstore/cre_go/internal/sumsub"

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
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		if err := runOnce(ctx, cfg, chain, sumClient); err != nil {
			log.Printf("SyncKycStatus run error: %v", err)
		}
	}

	if !*loop {
		run()
		return
	}

	log.Printf("SyncKycStatus worker started with interval=%dms", cfg.PollIntervalMS)
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		run()
		<-ticker.C
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

	fromBlock := uint64(0)
	if st.LastSyncBlock > 0 {
		fromBlock = st.LastSyncBlock + 1
	} else if latest > 2000 {
		fromBlock = latest - 2000
	}

	recentRequests, err := chain.QueryKycRequested(ctx, fromBlock, latest)
	if err != nil {
		return err
	}

	for _, ev := range recentRequests {
		key := strings.ToLower(ev.User.Hex())
		u := st.Users[key]
		u.UserID = ev.User.Hex()
		u.LastSeenRequestID = ev.RequestID.String()
		st.Users[key] = u
	}

	if len(st.Users) == 0 {
		log.Printf("SyncKycStatus: no users to check yet")
	}

	for key, userState := range st.Users {
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
		} else {
			log.Printf("user=%s status unchanged (%s)", userID, decision)
		}

		u := st.Users[key]
		u.UserID = userID
		u.LastReviewDecision = state.ReviewDecision(decision)
		u = state.TouchSyncTime(u)
		st.Users[key] = u
	}

	st.LastSyncBlock = latest
	return state.Write(cfg.StateFile, st)
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
