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

var (
	errNoPrivateKey   = errors.New("no private key found")
	errNoClearsign    = errors.New("no clearsigned message found")
	errClearPlaintext = errors.New("clearsigned text differs from message")
)

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

// Verify checks that both signatures in signed are valid for message under the
// binary public key, and that the clearsigned text is exactly message.
func Verify(public, message []byte, signed Signed) error {
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(public))
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(message), bytes.NewReader(signed.Detached), nil)
	if err != nil {
		return fmt.Errorf("verify detached signature: %w", err)
	}

	plaintext, err := verifyClear(keyring, signed.Clear)
	if err != nil {
		return err
	}

	if !bytes.Equal(plaintext, message) {
		return errClearPlaintext
	}

	return nil
}

// VerifyClear checks the clearsigned message against public, which is either
// an armored or a binary key, and returns the signed text.
func VerifyClear(public, signed []byte) ([]byte, error) {
	var (
		keyring openpgp.EntityList
		err     error
	)

	if bytes.HasPrefix(bytes.TrimSpace(public), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		keyring, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(public))
	} else {
		keyring, err = openpgp.ReadKeyRing(bytes.NewReader(public))
	}

	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	return verifyClear(keyring, signed)
}

func verifyClear(keyring openpgp.EntityList, signed []byte) ([]byte, error) {
	block, _ := clearsign.Decode(signed)
	if block == nil {
		return nil, errNoClearsign
	}

	_, err := block.VerifySignature(keyring, nil)
	if err != nil {
		return nil, fmt.Errorf("verify clearsigned message: %w", err)
	}

	return block.Plaintext, nil
}

// Sign signs message with SHA-256 because gpgv and sqv reject SHA-1.
func Sign(privateKey, message []byte) (Signed, error) {
	entity, err := readPrivateKey(privateKey)
	if err != nil {
		return Signed{}, err
	}

	cfg := &packet.Config{DefaultHash: crypto.SHA256}

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
