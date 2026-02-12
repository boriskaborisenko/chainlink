package cryptobox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

type envelope struct {
	Version        string `json:"version"`
	Nonce          string `json:"nonce"`
	EphemPublicKey string `json:"ephemPublicKey"`
	Ciphertext     string `json:"ciphertext"`
}

func EncryptForMetaMask(pubKeyB64, plaintext string) ([]byte, error) {
	pubRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode pubkey base64: %w", err)
	}
	if len(pubRaw) != 32 {
		return nil, fmt.Errorf("unexpected pubkey length: %d", len(pubRaw))
	}

	var recipientPub [32]byte
	copy(recipientPub[:], pubRaw)

	ephemPub, ephemPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	cipher := box.Seal(nil, []byte(plaintext), &nonce, &recipientPub, ephemPriv)

	payload := envelope{
		Version:        "x25519-xsalsa20-poly1305",
		Nonce:          base64.StdEncoding.EncodeToString(nonce[:]),
		EphemPublicKey: base64.StdEncoding.EncodeToString(ephemPub[:]),
		Ciphertext:     base64.StdEncoding.EncodeToString(cipher),
	}

	return json.Marshal(payload)
}
