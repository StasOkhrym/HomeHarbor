package protocol

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const companionRequestDomain = "homeharbor/companion-request/v1\x00"

var (
	ErrInvalidCompanionRequest = errors.New("invalid companion request")
	companionCanonicalMode     = func() cbor.EncMode {
		mode, err := cbor.CanonicalEncOptions().EncMode()
		if err != nil {
			panic(err)
		}

		return mode
	}()
)

// CompanionRequest is the replay-bound message signed by the trusted Mac
// companion when it reads the current snapshot. The method and path binding
// prevents a valid signature for one endpoint being reused elsewhere.
type CompanionRequest struct {
	Version uint16 `cbor:"version"`
	KeyID   string `cbor:"key_id"`
	Method  string `cbor:"method"`
	Path    string `cbor:"path"`
	Nonce   string `cbor:"nonce"`
}

// SignCompanionRequest signs a challenge-bound HTTP request for the trusted
// companion snapshot API. The signature contains no private device material.
func SignCompanionRequest(
	method, path, nonce, keyID string,
	privateKey ed25519.PrivateKey,
) ([]byte, error) {
	request := CompanionRequest{
		Version: CurrentVersion,
		KeyID:   strings.TrimSpace(keyID),
		Method:  method,
		Path:    path,
		Nonce:   nonce,
	}
	if len(privateKey) != ed25519.PrivateKeySize || request.KeyID == "" || request.Method == "" ||
		request.Path == "" ||
		request.Nonce == "" {
		return nil, ErrInvalidCompanionRequest
	}

	payload, err := companionCanonicalMode.Marshal(request)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(privateKey, append([]byte(companionRequestDomain), payload...)), nil
}

// VerifyCompanionRequest validates the exact method/path/nonce tuple before a
// handler consumes the nonce. Callers must still enforce single-use semantics.
func VerifyCompanionRequest(
	method, path, nonce, keyID string,
	signature []byte,
	publicKey ed25519.PublicKey,
) error {
	request := CompanionRequest{
		Version: CurrentVersion,
		KeyID:   strings.TrimSpace(keyID),
		Method:  method,
		Path:    path,
		Nonce:   nonce,
	}
	if len(publicKey) != ed25519.PublicKeySize || request.KeyID == "" || request.Method == "" ||
		request.Path == "" ||
		request.Nonce == "" ||
		len(signature) != ed25519.SignatureSize {
		return ErrInvalidCompanionRequest
	}

	payload, err := companionCanonicalMode.Marshal(request)
	if err != nil ||
		!ed25519.Verify(publicKey, append([]byte(companionRequestDomain), payload...), signature) {
		return ErrInvalidCompanionRequest
	}

	return nil
}
