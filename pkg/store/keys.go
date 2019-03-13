package store

import (
	"crypto"
	"crypto/rand"
        "crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"time"
	"gopkg.in/square/go-jose.v2"
)

// Keys hold signing keys.
type Keys struct {
	// Key for creating and verifying signatures. These may be nil.
	SigningKey    *jose.JSONWebKey
	SigningKeyPub *jose.JSONWebKey

	// Old signing keys which have been rotated but can still be used to validate
	// existing signatures.
	VerificationKeys []VerificationKey

	// The next time the signing key will rotate.
	//
	// For caching purposes, implementations MUST NOT update keys before this time.
	NextRotation time.Time
}

// VerificationKey is a rotated signing key which can still be used to verify
// signatures.
type VerificationKey struct {
	PublicKey *jose.JSONWebKey `json:"publicKey"`
	Expiry    time.Time        `json:"expiry"`
}

type RotationStrategy struct {
	// Time between rotations.
	rotationFrequency time.Duration

	// After being rotated how long should the key be kept around for validating
	// signatues?
	idTokenValidFor time.Duration
}

var (
	StaticRotation = RotationStrategy{
		rotationFrequency: time.Hour * 8760 * 100,
		idTokenValidFor:   time.Hour * 8760 * 100,
	}
	// DefaultRotation = RotationStrategy{}
)

type SigningAlgorithm struct {
	Name string
	// TODO: use crypto.Signer instead.
	Generator func() (crypto.PrivateKey, error)
}

var (
	RS256 = SigningAlgorithm{
		Name: "RS256",
		Generator: func() (crypto.PrivateKey, error) {
			return rsa.GenerateKey(rand.Reader, 2048)
		},
	}

	ES256 = SigningAlgorithm{
		Name: "ES256",
		Generator: func() (crypto.PrivateKey, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		},
	}
)
