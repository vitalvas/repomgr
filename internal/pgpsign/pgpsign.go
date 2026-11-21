package pgpsign

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type Key struct {
	Private []byte
	Public  []byte
}

// GenerateKey creates a v4 EdDSA key (algorithm 22) because gpgv 2.2 on
// Debian 10 does not support algorithm 27. Private is armored, Public is binary.
func GenerateKey(name, email string) (Key, error) {
	cfg := &packet.Config{
		Algorithm:   packet.PubKeyAlgoEdDSA,
		Curve:       packet.Curve25519,
		DefaultHash: crypto.SHA512,
	}

	entity, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		return Key{}, fmt.Errorf("generate entity: %w", err)
	}

	var pub, priv bytes.Buffer

	w, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		return Key{}, fmt.Errorf("armor private key: %w", err)
	}

	err = errors.Join(entity.Serialize(&pub), entity.SerializePrivate(w, cfg), w.Close())
	if err != nil {
		return Key{}, fmt.Errorf("serialize key: %w", err)
	}

	return Key{Private: priv.Bytes(), Public: pub.Bytes()}, nil
}
