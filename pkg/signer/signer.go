// Package signer implements Ethereum key management and signing functionality.
package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer provides key management, HD wallet operations, and cryptographic functions.
type Signer interface {
	// EthereumAddress returns the Ethereum address associated with the signer's public key.
	EthereumAddress() common.Address

	// SignTx signs an Ethereum transaction with the signer's private key.
	SignTx(transaction *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// Sign produces a raw ECDSA signature of the input hash.
	Sign(hash [32]byte) ([]byte, error)

	// MasterKey returns the HD wallet master key.
	MasterKey() *hdkeychain.ExtendedKey

	// DerivedKeys returns all derived child signers.
	DerivedKeys() []*signer

	// DeriveHDKey creates a new child key from a derivation path string.
	DeriveHDKey(path string) error

	// DeriveEthereumHDKey creates a child key using Ethereum's derivation path.
	DeriveEthereumHDKey(path accounts.DerivationPath) error

	// PublicKey returns the signer's public key.
	PublicKey() *ecdsa.PublicKey

	// PublicKeyFromBytes converts a byte slice to an ECDSA public key.
	PublicKeyFromBytes(pbKey []byte) (*ecdsa.PublicKey, error)

	// BytesFromPublicKey converts an ECDSA public key to bytes.
	BytesFromPublicKey(key *ecdsa.PublicKey) []byte

	// GetSharedSecret computes an ECDH shared secret with another public key.
	GetSharedSecret(their ecdsa.PublicKey) [32]byte

	// EncryptWithHash encrypts a message and returns its hash and ciphertext.
	EncryptWithHash(key [32]byte, nonce []byte, message []byte) ([32]byte, []byte, error)

	// DecryptMessage decrypts a message using a shared key and nonce.
	DecryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) (string, error)

	// ProveHDRelation creates a signature proving parent-child key relationship.
	ProveHDRelation(parentKey *hdkeychain.ExtendedKey, childKey *hdkeychain.ExtendedKey) ([]byte, error)

	// VerifyHDRelation validates a child relationship proof signature.
	VerifyHDRelation(parentPub, childPub, signature []byte, path string) (bool, error)
}

// signer implements the Signer interface.
type signer struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	masterKey  *hdkeychain.ExtendedKey
	childKeys  []*signer
}

// New creates a new signer from a private key hex string
func New(nodePrivateKey string) (Signer, error) {
	if len(strings.TrimSpace(nodePrivateKey)) == 0 {
		return nil, fmt.Errorf("node private key cannot be empty")
	}

	privateKey, err := crypto.HexToECDSA(nodePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error generating private key from hex: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to generate public key")
	}

	s := &signer{
		publicKey:  publicKeyECDSA,
		privateKey: privateKey,
	}

	// Initialize the HD master key
	masterKey, err := s.InitHDMaster()
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}
	s.masterKey = masterKey

	return s, nil
}

// NewKey generates a new random private key
func NewKey() (string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("unable to generate a new private key: %w", err)
	}
	// Return hex-encoded private key, skipping the 0x prefix
	return hexutil.Encode(crypto.FromECDSA(privateKey))[2:], nil
}

// Core Ethereum operations
func (c *signer) EthereumAddress() common.Address {
	return crypto.PubkeyToAddress(*c.publicKey)
}

// SignTx signs an ethereum transaction.
func (c *signer) SignTx(transaction *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	txSigner := types.NewLondonSigner(chainID)
	signedTx, err := types.SignTx(transaction, txSigner, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}
	return signedTx, nil
}

// Key management operations
func (c *signer) PublicKey() *ecdsa.PublicKey {
	return c.publicKey
}

func (c *signer) MasterKey() *hdkeychain.ExtendedKey {
	return c.masterKey
}

func (c *signer) DerivedKeys() []*signer {
	return c.childKeys
}

// Encryption operations
func (c *signer) GetSharedSecret(their ecdsa.PublicKey) [32]byte {
	sharedKey, _ := their.Curve.ScalarMult(their.X, their.Y, c.privateKey.D.Bytes())
	return sha256.Sum256(sharedKey.Bytes())
}

// EncryptWithHash using the shared key, nonce and message.
func (c *signer) EncryptWithHash(
	key [32]byte, nonce []byte, message []byte,
) ([32]byte, []byte, error) {

	aesgcm, err := getCipherMode(key[:])
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("error getting cipher mode: %w", err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, message, nil)
	return sha256.Sum256(ciphertext), ciphertext, nil
}

// DecryptMessage using sharedKey, ciphered text and the nonce used to encrypt it.
func (c *signer) DecryptMessage(
	sharedKey [32]byte, cipherText []byte, nonce []byte,
) (string, error) {

	aesgcm, err := getCipherMode(sharedKey[:])
	if err != nil {
		return "", fmt.Errorf("error getting cipher mode: %w", err)
	}
	deciphered, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", fmt.Errorf("error deciphering the message: %w", err)
	}
	return string(deciphered), nil
}

// Helper functions moved to package level
func getCipherMode(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error generating cipher block: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}
	return aesgcm, nil
}

// Sign the hash with the signer's private key (non-EIP155).
func (c *signer) Sign(hash [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("error signing using private key: %w", err)
	}
	// combine r and s
	return append(r.Bytes(), s.Bytes()...), nil
}

func (c *signer) PublicKeyFromBytes(pbKey []byte) (*ecdsa.PublicKey, error) {
	return crypto.UnmarshalPubkey(pbKey)
}

func (c *signer) BytesFromPublicKey(key *ecdsa.PublicKey) []byte {
	return crypto.FromECDSAPub(key)
}
