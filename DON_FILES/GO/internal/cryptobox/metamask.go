package cryptobox

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// EncryptForSessionKey packs ciphertext in the same format as TS worker:
// nonce(24) || ephemeralPubKey(32) || ciphertext(n).
func EncryptForSessionKey(recipientPubKey []byte, plaintext string) ([]byte, error) {
	if len(recipientPubKey) != 32 {
		return nil, fmt.Errorf("unexpected pubkey length: %d", len(recipientPubKey))
	}

	var recipientPub [32]byte
	copy(recipientPub[:], recipientPubKey)

	ephemPub, ephemPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	cipher := box.Seal(nil, []byte(plaintext), &nonce, &recipientPub, ephemPriv)
	packet := make([]byte, 0, len(nonce)+len(ephemPub)+len(cipher))
	packet = append(packet, nonce[:]...)
	packet = append(packet, ephemPub[:]...)
	packet = append(packet, cipher...)
	return packet, nil
}
