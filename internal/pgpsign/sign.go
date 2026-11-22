package pgpsign

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type Signed struct {
	Clear    []byte
	Detached []byte
}

var errNoPrivateKey = errors.New("no private key found")

func readPrivateKey(privateKey []byte) (*openpgp.Entity, error) {
	list, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateKey))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	if len(list) == 0 || list[0].PrivateKey == nil {
		return nil, fmt.Errorf("read private key: %w", errNoPrivateKey)
	}

	return list[0], nil
}

// PublicKey returns the binary public key in the same form GenerateKey produces.
func PublicKey(privateKey []byte) ([]byte, error) {
	entity, err := readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	var pub bytes.Buffer

	err = entity.Serialize(&pub)
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}

	return pub.Bytes(), nil
}

// Sign signs message with SHA-512 because gpgv and sqv reject SHA-1.
func Sign(privateKey, message []byte) (Signed, error) {
	entity, err := readPrivateKey(privateKey)
	if err != nil {
		return Signed{}, err
	}

	cfg := &packet.Config{DefaultHash: crypto.SHA512}

	var clearBuf, detached bytes.Buffer

	w, err := clearsign.Encode(&clearBuf, entity.PrivateKey, cfg)
	if err != nil {
		return Signed{}, fmt.Errorf("clearsign encode: %w", err)
	}

	_, writeErr := w.Write(message)
	closeErr := w.Close()
	detachErr := openpgp.ArmoredDetachSign(&detached, entity, bytes.NewReader(message), cfg)

	err = errors.Join(writeErr, closeErr, detachErr)
	if err != nil {
		return Signed{}, fmt.Errorf("sign message: %w", err)
	}

	return Signed{Clear: clearBuf.Bytes(), Detached: detached.Bytes()}, nil
}
