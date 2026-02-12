package main

import (
	"context"
	"flag"
	"log"
	"strings"
	"time"

	"passstore/cre_go/internal/config"
	"passstore/cre_go/internal/cryptobox"
	"passstore/cre_go/internal/eth"
	"passstore/cre_go/internal/state"
	"passstore/cre_go/internal/sumsub"
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
			log.Printf("IssueSdkToken run error: %v", err)
		}
	}

	if !*loop {
		run()
		return
	}

	log.Printf("IssueSdkToken worker started with interval=%dms", cfg.PollIntervalMS)
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
	if st.LastIssueTokenBlock > 0 {
		fromBlock = st.LastIssueTokenBlock + 1
	} else if latest > 2000 {
		fromBlock = latest - 2000
	}

	events, err := chain.QueryKycRequested(ctx, fromBlock, latest)
	if err != nil {
		return err
	}

	if len(events) == 0 {
		log.Printf("IssueSdkToken: no KycRequested events in blocks %d-%d", fromBlock, latest)
	}

	for _, ev := range events {
		if err := processEvent(ctx, cfg, chain, sumClient, ev, &st); err != nil {
			log.Printf("process requestId=%s failed: %v", ev.RequestID.String(), err)
		}
	}

	st.LastIssueTokenBlock = latest
	return state.Write(cfg.StateFile, st)
}

func processEvent(
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

	level := ev.LevelName
	if level == "" {
		level = cfg.DefaultLevelName
	}

	token, err := sumClient.GenerateSDKToken(ctx, ev.User.Hex(), level, cfg.TokenTTLSeconds)
	if err != nil {
		return err
	}

	ciphertext, err := cryptobox.EncryptForMetaMask(string(pubKeyBytes), token)
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
