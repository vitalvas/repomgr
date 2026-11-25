package rpmfile

import (
	"fmt"
	"regexp"
	"strings"
)

const minPayloadDigestLen int = 40

var payloadDigestRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// verifyPayload checks every payload digest in tag 5092 against sum, the
// SHA-256 of the payload. Nothing is checked when the tag is absent.
func (h header) verifyPayload(sum string) error {
	digests, ok, err := h.strings(tagPayload, "payload digest tag 5092")
	if !ok || err != nil {
		return err
	}

	for _, d := range digests {
		if len(d)%2 != 0 || len(d) < minPayloadDigestLen || !payloadDigestRe.MatchString(d) {
			return fmt.Errorf("%w: payload digest tag 5092 element %q is malformed", ErrInvalidField, d)
		}

		if !strings.EqualFold(d, sum) {
			return fmt.Errorf("%w: payload digest tag 5092 element %s does not match the payload SHA-256 %s", ErrInvalidField, d, sum)
		}
	}

	return nil
}
