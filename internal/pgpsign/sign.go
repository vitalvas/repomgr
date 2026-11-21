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

// Sign signs message with SHA-512 because gpgv and sqv reject SHA-1.
func Sign(privateKey, message []byte) (Signed, error) {
	list, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateKey))
	if err != nil {
		return Signed{}, fmt.Errorf("read private key: %w", err)
	}

	if len(list) == 0 || list[0].PrivateKey == nil {
		return Signed{}, fmt.Errorf("read private key: %w", errNoPrivateKey)
	}

	cfg := &packet.Config{DefaultHash: crypto.SHA512}

	var clearBuf, detached bytes.Buffer

	w, err := clearsign.Encode(&clearBuf, list[0].PrivateKey, cfg)
	if err != nil {
		return Signed{}, fmt.Errorf("clearsign encode: %w", err)
	}

	_, writeErr := w.Write(message)
	closeErr := w.Close()
	detachErr := openpgp.ArmoredDetachSign(&detached, list[0], bytes.NewReader(message), cfg)

	err = errors.Join(writeErr, closeErr, detachErr)
	if err != nil {
		return Signed{}, fmt.Errorf("sign message: %w", err)
	}

	return Signed{Clear: clearBuf.Bytes(), Detached: detached.Bytes()}, nil
}
