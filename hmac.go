package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	authorizationHeaderPieces = 3
)

var (
	// ErrNoAuthHeader is returned when authenticating a request that has no Authorization header set.
	ErrNoAuthHeader = errors.New("no Authorization header")
	// ErrMalformedAuthHeader is returned when authenticating a request that has an Authorization header,
	// but in an invalid format.
	ErrMalformedAuthHeader = errors.New("malformed Authorization header")
	// ErrUnknownOrgKey is returned when the Authorization header has an organization key that isn't
	// recognised.
	ErrUnknownOrgKey = errors.New("unknown organization portion of Authorization header")
	// ErrInvalidVersion is returned when the Authorization header has a version that isn't supported.
	ErrInvalidVersion = errors.New("invalid version in Authorization header")
	// ErrNoDateHeader is returned when authenticating a request that has no Date header set.
	ErrNoDateHeader = errors.New("no Date header")
	// ErrMalformedDateHeader is returned when authenticating a request that has a Date header, but in
	// an invalid format.
	ErrMalformedDateHeader = errors.New("invalid format for Date header")
	// ErrDateSkew is returned when authenticating a request with a Date header too far before or after
	// the current time.
	ErrDateSkew = errors.New("Date header value is too far from current time")
	// ErrSignatureMismatch is returned when the signature in an Authorization header does not match the
	// request.
	ErrSignatureMismatch = errors.New("invalid signature for request")
	// ErrUnknownKey is returned when the signature key presented in an Authorization header is not
	// recognised.
	ErrUnknownKey = errors.New("unknown key presented to be signed against")
	// ErrContentMismatch is returned when the hash of the content that is calculated does not match the
	// hash claimed in the headers.
	ErrContentMismatch = errors.New("content does not match claimed hash")
)

// Signer holds the common configuration for authenticating requests.
type Signer struct {
	OrgKey  string        // the string to use as the org when constructing the header
	MaxSkew time.Duration // the maximum difference between the current time and the Date header
	Secret  []byte        // the secret to use to generate the signature
	Key     string        // the key to use to signal which secret is being used
}

// Sign generates a cryptographic signature to authenticate the request.
func (s Signer) Sign(r *http.Request) string {
	return base64.StdEncoding.EncodeToString(hmac.New(sha256.New, s.Secret).Sum([]byte(buildStringToSign(r))))
}

// AuthenticateRequest reads the Authorization header to authenticate the request.
// The header is expected to be in the following format:
//
// 	{ORG} v1 {KEY}:{SIG}
//
// Where {ORG} is the OrgKey property of `s` and {SIG} is the base 64 encoded
// signature for the request.
func (s Signer) AuthenticateRequest(r *http.Request, contentHash string) error {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return ErrNoAuthHeader
	}
	pieces := strings.Split(header, " ")
	if len(pieces) != authorizationHeaderPieces {
		return ErrMalformedAuthHeader
	}
	if pieces[0] != s.OrgKey {
		return ErrUnknownOrgKey
	}
	if pieces[1] != "v1" {
		return ErrInvalidVersion
	}
	pieces = strings.Split(pieces[2], ":")
	if len(pieces) != 2 { //nolint:gomnd // there should only be 2 pieces, and this is the only place that number is used
		return ErrMalformedAuthHeader
	}
	if pieces[0] != s.Key {
		return ErrUnknownKey
	}
	sig := pieces[1]
	dateStr := strings.TrimSpace(r.Header.Get("Date"))
	if dateStr == "" {
		return ErrNoDateHeader
	}
	date, err := time.Parse(time.RFC1123, dateStr)
	if err != nil {
		return ErrMalformedDateHeader
	}
	now := time.Now()
	if now.Sub(date) > s.MaxSkew || date.Sub(now) > s.MaxSkew {
		return ErrDateSkew
	}
	if r.Header.Get("Content-SHA256") != contentHash {
		return ErrContentMismatch
	}
	expSig := s.Sign(r)
	if subtle.ConstantTimeCompare([]byte(expSig), []byte(sig)) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

func buildStringToSign(r *http.Request) string {
	return strings.Join([]string{
		r.Method,
		r.Header.Get("Content-SHA256"),
		r.Header.Get("Content-Type"),
		r.Header.Get("Date"),
		r.URL.Path,
	}, "\n")
}
