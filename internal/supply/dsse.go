package supply

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/sandy-t-shelvan/govcode/internal/sign"
)

// DSSE (Dead Simple Signing Envelope, v1.0) as used by in-toto and SLSA.
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
//
// The signature covers PAE(payloadType, payload), never the base64 text,
// so a verifier cannot be tricked by re-encoding.

type Envelope struct {
	PayloadType string         `json:"payloadType"`
	Payload     string         `json:"payload"` // standard base64
	Signatures  []EnvelopeSign `json:"signatures"`
}

type EnvelopeSign struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // standard base64
}

const InTotoPayloadType = "application/vnd.in-toto+json"

// PAE is the DSSE pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in ASCII decimal.
func PAE(payloadType string, payload []byte) []byte {
	b := []byte("DSSEv1 ")
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(payload)), 10)
	b = append(b, ' ')
	return append(b, payload...)
}

// SignEnvelope signs payload with s and returns a one-signature envelope.
func SignEnvelope(s sign.Signer, payloadType string, payload []byte) (*Envelope, error) {
	sig, err := s.Sign(PAE(payloadType, payload))
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []EnvelopeSign{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// VerifyEnvelope returns the payload if at least one signature verifies
// against a trusted key. Key IDs are hints only: every trusted key is tried
// against every signature, so a wrong or missing keyid cannot cause a
// false accept or a false reject.
func VerifyEnvelope(env *Envelope, wantType string, trusted []ed25519.PublicKey) ([]byte, string, error) {
	if env.PayloadType != wantType {
		return nil, "", fmt.Errorf("payloadType %q, want %q", env.PayloadType, wantType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return nil, "", errors.New("envelope has no signatures")
	}
	msg := PAE(env.PayloadType, payload)
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range trusted {
			if ed25519.Verify(k, msg, sig) {
				return payload, sign.KeyID(k), nil
			}
		}
	}
	return nil, "", errors.New("no envelope signature verifies against a trusted key")
}

// ParseEnvelopes reads an in-toto bundle: one JSON envelope per line
// (.intoto.jsonl), or a single JSON envelope.
func ParseEnvelopes(data []byte) ([]*Envelope, error) {
	var out []*Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var e Envelope
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	if len(out) == 0 {
		return nil, errors.New("no envelopes")
	}
	return out, nil
}
