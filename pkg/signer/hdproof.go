package signer

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
)

// ProveHDRelation signs a child's public key with the parent's private key.
// The signature can be verified by anyone with access to both public keys.
// Requires: parentKey must be a private extended key.
func (c *signer) ProveHDRelation(
	parentKey *hdkeychain.ExtendedKey,
	childKey *hdkeychain.ExtendedKey,
) ([]byte, error) {
	if parentKey == nil || !parentKey.IsPrivate() {
		return nil, errors.New("parent must be a private extended key")
	}

	childPubKey, err := childKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get child public key: %w", err)
	}

	// Convert child's public key to Ethereum's uncompressed format
	childPubBytes := crypto.FromECDSAPub(&ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     childPubKey.X(),
		Y:     childPubKey.Y(),
	})

	msgHash := crypto.Keccak256(childPubBytes)
	signature, err := crypto.Sign(msgHash, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// VerifyHDRelation validates a signature produced by ProveHDRelation.
// Expects: parentPub and childPub as 65-byte uncompressed public keys,
// signature as 65-byte [R || S || V] format from crypto.Sign.
func (c *signer) VerifyHDRelation(
	parentPub, childPub, signature []byte,
	path string, // Kept for interface compatibility
) (bool, error) {
	if len(parentPub) != 65 || len(childPub) != 65 {
		return false, fmt.Errorf(
			"invalid pubkey length (parent=%d, child=%d)",
			len(parentPub),
			len(childPub),
		)
	}

	msgHash := crypto.Keccak256(childPub)
	recoveredPub, err := crypto.Ecrecover(msgHash, signature)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %w", err)
	}

	recoveredPubKey, err := crypto.UnmarshalPubkey(recoveredPub)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal recovered pubkey: %w", err)
	}

	parentPubKey, err := crypto.UnmarshalPubkey(parentPub)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal parent pubkey: %w", err)
	}

	return recoveredPubKey.X.Cmp(parentPubKey.X) == 0 &&
		recoveredPubKey.Y.Cmp(parentPubKey.Y) == 0, nil
}
