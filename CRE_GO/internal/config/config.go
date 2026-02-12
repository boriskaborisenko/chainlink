package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	RPCURL                string
	CRESignerPK           string
	BrokerAddress         string
	RegistryAddress       string
	SumsubBaseURL         string
	SumsubAppToken        string
	SumsubSecretKey       string
	SumsubSDKTokenPath    string
	SumsubStatusPathTmpl  string
	KYCLevelName          string
	TokenTTLSeconds       int
	PollIntervalMS        int
	AttestationExpiryDays int
	FlagHuman             uint64
	StateFile             string
}

func Load() (Config, error) {
	_ = godotenv.Load()

	cfg := Config{}
	var err error

	if cfg.RPCURL, err = required("RPC_URL"); err != nil {
		return cfg, err
	}
	if cfg.CRESignerPK, err = required("CRE_SIGNER_PK"); err != nil {
		return cfg, err
	}
	if cfg.BrokerAddress, err = required("KYC_BROKER_ADDRESS"); err != nil {
		return cfg, err
	}
	if cfg.RegistryAddress, err = required("PASS_REGISTRY_ADDRESS"); err != nil {
		return cfg, err
	}
	if cfg.SumsubAppToken, err = required("SUMSUB_APP_TOKEN"); err != nil {
		return cfg, err
	}
	if cfg.SumsubSecretKey, err = required("SUMSUB_SECRET_KEY"); err != nil {
		return cfg, err
	}

	cfg.SumsubBaseURL = optional("SUMSUB_BASE_URL", "https://api.sumsub.com")
	cfg.SumsubSDKTokenPath = optional("SUMSUB_SDK_TOKEN_PATH", "/resources/accessTokens/sdk")
	cfg.SumsubStatusPathTmpl = optional("SUMSUB_STATUS_PATH_TEMPLATE", "/resources/applicants/-;externalUserId={userId}/one")
	cfg.KYCLevelName = optional("KYC_LEVEL_NAME", optional("DEFAULT_LEVEL_NAME", "basic-kyc"))
	cfg.TokenTTLSeconds = optionalInt("TOKEN_TTL_SECONDS", 600)
	cfg.PollIntervalMS = optionalInt("POLL_INTERVAL_MS", 120000)
	cfg.AttestationExpiryDays = optionalInt("ATTESTATION_EXPIRATION_DAYS", 180)
	cfg.FlagHuman = uint64(optionalInt("FLAG_HUMAN", 1))
	cfg.StateFile = optional("STATE_FILE", ".cre-go-state.json")

	return cfg, nil
}

func required(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("missing required env var: %s", name)
	}
	return v, nil
}

func optional(name, fallback string) string {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	return v
}

func optionalInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}
