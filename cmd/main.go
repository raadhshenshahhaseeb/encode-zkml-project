// Command main demonstrates HD wallet key derivation and relationship proving.
package main

import (
	"fmt"
	"log"

	"github.com/encode-bootcamp/zkml/config"
	"github.com/encode-bootcamp/zkml/pkg/signer"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	_, err := config.Init()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// Create parent signer
	parentKey, err := signer.NewKey()
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	fmt.Printf("Generated parent private key: %s\n", parentKey)

	parentSigner, err := signer.New(parentKey)
	if err != nil {
		log.Fatalf("Failed to create parent signer: %v", err)
	}
	fmt.Printf("Parent address: %s\n", parentSigner.EthereumAddress().Hex())

	// Derive child keys using different paths
	paths := []string{
		"m/44'/60'/0'/0/0", // Standard Ethereum path
		"m/44'/60'/0'/0/1", // Next address in sequence
	}

	for i, path := range paths {
		fmt.Printf("\nDerivation Path %d: %s\n", i+1, path)

		// Derive child key
		err := parentSigner.DeriveHDKey(path)
		if err != nil {
			log.Fatalf("Failed to derive child key %d: %v", i+1, err)
		}
	}

	// Get all derived child keys
	childKeys := parentSigner.DerivedKeys()
	fmt.Printf("\nDerived %d child keys\n", len(childKeys))

	// Demonstrate relationship proving
	parentMasterKey := parentSigner.MasterKey()
	if parentMasterKey == nil {
		log.Fatal("Parent master key is nil")
	}

	for i, childSigner := range childKeys {
		fmt.Printf("\nVerifying Child %d:\n", i+1)
		fmt.Printf("Child Address: %s\n", childSigner.EthereumAddress().Hex())

		childMasterKey := childSigner.MasterKey()
		if childMasterKey == nil {
			log.Fatalf("Child %d master key is nil", i+1)
		}

		// Generate proof
		signature, err := parentSigner.ProveHDRelation(parentMasterKey, childMasterKey)
		if err != nil {
			log.Fatalf("Failed to prove relationship for child %d: %v", i+1, err)
		}
		fmt.Printf("Generated proof signature\n")

		// Get public keys in the correct format
		parentPubKey := crypto.FromECDSAPub(parentSigner.PublicKey())
		childPubKey := crypto.FromECDSAPub(childSigner.PublicKey())

		// Verify the relationship
		isValid, err := parentSigner.VerifyHDRelation(
			parentPubKey,
			childPubKey,
			signature,
			paths[i],
		)
		if err != nil {
			log.Fatalf("Failed to verify relationship: %v", err)
		}

		if isValid {
			fmt.Printf("Successfully verified child relationship\n")
		} else {
			fmt.Printf("Failed to verify child relationship\n")
		}
	}
}
