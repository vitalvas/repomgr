package rpmfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/repomgr/internal/rpmtest"
)

func payloadSum(p rpmtest.Package) string {
	sum := sha256.Sum256(p.Payload)

	return hex.EncodeToString(sum[:])
}

func TestParsePayloadDigest(t *testing.T) {
	sum := payloadSum(basePackage())
	other := strings.Repeat("0", 64)
	arr := func(v ...string) rpmtest.Tag { return rpmtest.Tag{ID: 5092, Type: 8, Value: v} }

	tests := []struct {
		name    string
		tag     *rpmtest.Tag
		payload []byte
		want    string
	}{
		{"match lower", ptr(arr(sum)), nil, ""},
		{"match upper", ptr(arr(strings.ToUpper(sum))), nil, ""},
		{"mismatch", ptr(arr(other)), nil, "5092"},
		{"second mismatches", ptr(arr(sum, other)), nil, "5092"},
		{"both match", ptr(arr(sum, strings.ToUpper(sum))), nil, ""},
		{"odd length", ptr(arr(sum[:63])), nil, "5092"},
		{"38 characters", ptr(arr(sum[:38])), nil, "5092"},
		{"non hex", ptr(arr(strings.Replace(sum, sum[:1], "g", 1))), nil, "5092"},
		{"wrong type", &rpmtest.Tag{ID: 5092, Type: 6, Value: sum}, nil, "5092"},
		{"no tag", nil, []byte("anything"), ""},
		{"truncated payload", ptr(arr(sum)), []byte("payload"), "5092"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePackage()
			if tt.tag != nil {
				p.Tags = append(p.Tags, *tt.tag)
			}

			if tt.payload != nil {
				p.Payload = tt.payload
			}

			_, err := Parse(bytes.NewReader(build(t, p)))
			if tt.want == "" {
				require.NoError(t, err)

				return
			}

			assert.ErrorIs(t, err, ErrInvalidField)
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func ptr[T any](v T) *T { return &v }
