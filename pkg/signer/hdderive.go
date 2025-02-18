package signer

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

// InitHDMaster creates a master HD key from the signer's private key.
func (c *signer) InitHDMaster() (*hdkeychain.ExtendedKey, error) {
	privBytes := crypto.FromECDSA(c.privateKey)
	masterKey, err := hdkeychain.NewMaster(privBytes, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create HD master key: %w", err)
	}
	return masterKey, nil
}

// deriveFromPath derives a child key from a master key using BIP32 indices.
func (c *signer) deriveFromPath(masterKey *hdkeychain.ExtendedKey, indices []uint32) (*hdkeychain.ExtendedKey, error) {
	childKey := masterKey
	for _, index := range indices {
		nextKey, err := childKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child index %d: %w", index&0x7fffffff, err)
		}
		childKey = nextKey
	}

	if !childKey.IsPrivate() {
		return nil, errors.New("child key is not private")
	}

	return childKey, nil
}

// createDerivedSigner converts an HD key to a new signer instance.
func (c *signer) createDerivedSigner(childKey *hdkeychain.ExtendedKey) error {
	btcecPriv, err := childKey.ECPrivKey()
	if err != nil {
		return fmt.Errorf("failed to get private key bytes: %w", err)
	}

	ecdsaPrivKey, err := crypto.ToECDSA(btcecPriv.Serialize())
	if err != nil {
		return fmt.Errorf("failed to convert child key to ECDSA: %w", err)
	}

	child := &signer{
		privateKey: ecdsaPrivKey,
		publicKey:  &ecdsaPrivKey.PublicKey,
		masterKey:  childKey,
	}

	c.childKeys = append(c.childKeys, child)
	return nil
}

// DeriveHDKey derives a child key using a string path
func (c *signer) DeriveHDKey(pathStr string) error {
	if pathStr == "" {
		pathStr = "m/44'/60'/0'/0/0"
	}
	derivationPath, err := accounts.ParseDerivationPath(pathStr)
	if err != nil {
		return fmt.Errorf("failed to parse derivation path %q: %w", pathStr, err)
	}

	if c.masterKey == nil {
		return fmt.Errorf("master key not initialized")
	}

	childKey, err := c.deriveFromPath(c.masterKey, derivationPath)
	if err != nil {
		return err
	}

	return c.createDerivedSigner(childKey)
}

// DeriveEthereumHDKey derives a child key using an Ethereum derivation path
func (c *signer) DeriveEthereumHDKey(path accounts.DerivationPath) error {
	if path == nil {
		path = accounts.DefaultRootDerivationPath
	}

	if c.masterKey == nil {
		return fmt.Errorf("master key not initialized")
	}

	childKey, err := c.deriveFromPath(c.masterKey, path)
	if err != nil {
		return err
	}

	return c.createDerivedSigner(childKey)
}
