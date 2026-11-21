package pgpsign

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleRelease = "Origin: repomgr\nSuite: stable\nCodename: stable\nArchitectures: amd64 arm64\nComponents: main\n"

func TestSign(t *testing.T) {
	key, err := GenerateKey("Repo Signer", "repo@example.com")
	require.NoError(t, err)

	pub, err := openpgp.ReadKeyRing(bytes.NewReader(key.Public))
	require.NoError(t, err)

	message := []byte(sampleRelease)

	signed, err := Sign(key.Private, message)
	require.NoError(t, err)

	t.Run("armor headers", func(t *testing.T) {
		assert.True(t, bytes.HasPrefix(signed.Clear, []byte("-----BEGIN PGP SIGNED MESSAGE-----")))
		assert.True(t, bytes.HasPrefix(signed.Detached, []byte("-----BEGIN PGP SIGNATURE-----")))
	})

	t.Run("clearsign verifies", func(t *testing.T) {
		block, _ := clearsign.Decode(signed.Clear)
		require.NotNil(t, block)

		_, err := block.VerifySignature(pub, nil)
		require.NoError(t, err)

		assert.Equal(t, message, block.Plaintext)
	})

	t.Run("clearsign without trailing newline", func(t *testing.T) {
		bare := bytes.TrimSuffix(message, []byte("\n"))

		s, err := Sign(key.Private, bare)
		require.NoError(t, err)

		block, _ := clearsign.Decode(s.Clear)
		require.NotNil(t, block)

		_, err = block.VerifySignature(pub, nil)
		require.NoError(t, err)

		assert.Equal(t, bare, block.Plaintext)
	})

	t.Run("clearsign uses SHA-512", func(t *testing.T) {
		block, _ := clearsign.Decode(signed.Clear)
		require.NotNil(t, block)

		sig, err := packet.Read(block.ArmoredSignature.Body)
		require.NoError(t, err)

		s, ok := sig.(*packet.Signature)
		require.True(t, ok)
		assert.Equal(t, crypto.SHA512, s.Hash)
	})

	t.Run("detached verifies", func(t *testing.T) {
		_, err := openpgp.CheckArmoredDetachedSignature(pub, bytes.NewReader(message), bytes.NewReader(signed.Detached), nil)
		require.NoError(t, err)
	})

	t.Run("detached fails for changed message", func(t *testing.T) {
		changed := bytes.Clone(message)
		changed[0] ^= 1

		_, err := openpgp.CheckArmoredDetachedSignature(pub, bytes.NewReader(changed), bytes.NewReader(signed.Detached), nil)
		assert.Error(t, err)
	})

	t.Run("detached uses SHA-512", func(t *testing.T) {
		block, err := armor.Decode(bytes.NewReader(signed.Detached))
		require.NoError(t, err)

		sig, err := packet.Read(block.Body)
		require.NoError(t, err)

		s, ok := sig.(*packet.Signature)
		require.True(t, ok)
		assert.Equal(t, crypto.SHA512, s.Hash)
	})

	t.Run("invalid private key", func(t *testing.T) {
		var pubArmored bytes.Buffer

		w, err := armor.Encode(&pubArmored, openpgp.PublicKeyType, nil)
		require.NoError(t, err)
		require.NoError(t, pub[0].Serialize(w))
		require.NoError(t, w.Close())

		cases := []struct {
			name  string
			input []byte
			want  error
		}{
			{"garbage", []byte("not a key"), nil},
			{"empty", nil, nil},
			{"binary public key", key.Public, nil},
			{"armored public", pubArmored.Bytes(), errNoPrivateKey},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := Sign(tc.input, message)
				require.Error(t, err)

				if tc.want != nil {
					assert.ErrorIs(t, err, tc.want)
				}
			})
		}
	})
}

func BenchmarkSign(b *testing.B) {
	key, err := GenerateKey("Repo Signer", "repo@example.com")
	require.NoError(b, err)

	message := []byte(sampleRelease)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := Sign(key.Private, message); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzSign(f *testing.F) {
	key, err := GenerateKey("Repo Signer", "repo@example.com")
	require.NoError(f, err)

	pub, err := openpgp.ReadKeyRing(bytes.NewReader(key.Public))
	require.NoError(f, err)

	f.Add([]byte(sampleRelease))
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----\n- dash\n"))

	f.Fuzz(func(t *testing.T, message []byte) {
		signed, err := Sign(key.Private, message)
		require.NoError(t, err)

		_, err = openpgp.CheckArmoredDetachedSignature(pub, bytes.NewReader(message), bytes.NewReader(signed.Detached), nil)
		assert.NoError(t, err)
	})
}
