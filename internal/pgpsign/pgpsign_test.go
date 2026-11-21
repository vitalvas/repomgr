package pgpsign

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var curve25519OID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}

func firstPacketBody(t *testing.T, data []byte) []byte {
	t.Helper()

	require.GreaterOrEqual(t, len(data), 3)

	first := int(data[1])
	switch {
	case first < 192:
		return data[2 : 2+first]
	case first < 224:
		length := (first-192)<<8 + int(data[2]) + 192
		return data[3 : 3+length]
	}

	require.Fail(t, "unexpected length header", "%#x", data[1])

	return nil
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey("Repo Signer", "repo@example.com")
	require.NoError(t, err)

	t.Run("public key packet is v4 EdDSA Curve25519", func(t *testing.T) {
		require.Equal(t, byte(0xc6), key.Public[0])

		body := firstPacketBody(t, key.Public)
		require.Greater(t, len(body), 6)
		assert.Equal(t, byte(0x04), body[0])
		assert.Equal(t, byte(0x16), body[5])
		assert.True(t, bytes.Contains(body, curve25519OID))
	})

	t.Run("binary public key reads back", func(t *testing.T) {
		list, err := openpgp.ReadKeyRing(bytes.NewReader(key.Public))
		require.NoError(t, err)
		require.Len(t, list, 1)

		require.Len(t, list[0].Identities, 1)

		for _, id := range list[0].Identities {
			assert.Equal(t, "Repo Signer", id.UserId.Name)
			assert.Equal(t, "repo@example.com", id.UserId.Email)
		}
	})

	t.Run("armored private key reads back", func(t *testing.T) {
		assert.True(t, bytes.HasPrefix(key.Private, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")))

		list, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key.Private))
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.NotNil(t, list[0].PrivateKey)
		assert.False(t, list[0].PrivateKey.Encrypted)
	})

	t.Run("invalid characters fail", func(t *testing.T) {
		for _, tc := range []struct{ name, email string }{
			{"bad<name", "a@b.c"},
			{"name", "a@b.c>"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := GenerateKey(tc.name, tc.email)
				assert.Error(t, err)
			})
		}
	})
}

func BenchmarkGenerateKey(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := GenerateKey("Repo Signer", "repo@example.com"); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzGenerateKey(f *testing.F) {
	f.Add("Repo Signer", "repo@example.com")
	f.Add("", "")
	f.Add("a<b", "c")

	f.Fuzz(func(t *testing.T, name, email string) {
		key, err := GenerateKey(name, email)
		if err != nil {
			return
		}

		list, err := openpgp.ReadKeyRing(bytes.NewReader(key.Public))
		require.NoError(t, err)
		assert.Len(t, list, 1)
	})
}
