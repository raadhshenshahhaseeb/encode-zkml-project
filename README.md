# Hierarchical Deterministic (HD) Wallet Demonstration

This repository contains a simple demonstration of Hierarchical Deterministic (HD) wallet derivation and parent–child relationship proving in Go. It showcases:

- Creation of an HD master key from a single private key  
- Derivation of child keys using arbitrary BIP32/BIP44‐style paths  
- Proof of the relationship between a parent (master) key and any child key  
- Verification of that proof by recovering and comparing public keys  

> **Note:** This code is intended for educational purposes. It is not production‐ready and should be used with caution for any sensitive or real‐world applications.

---

## Table of Contents

1. [Overview](#overview)  
2. [File Structure](#file-structure)  
3. [Usage](#usage)  
4. [Technical Details](#technical-details)  
5. [Security Notice](#security-notice)  
6. [License](#license)

---

## Overview

A Hierarchical Deterministic (HD) wallet allows you to derive multiple child keys from a single master seed. This project demonstrates:

- **HD Key Generation**: Deriving the master key from an existing ECDSA private key.  
- **Child Key Derivation**: Producing multiple child keys according to standard derivation paths (such as `m/44'/60'/0'/0/0`) typically used in Ethereum.  
- **Proof of Parent–Child Relationship**: Generating and verifying signatures that confirm a given child key is derived from a specific parent key.  

---

## File Structure

1. **`signer.go`**  
   Defines the `Signer` interface and provides the core signing, encryption, and utility methods:
   - **`Sign(...)`**: Raw ECDSA signature over a 32‐byte hash  
   - **`SignTx(...)`**: EIP‐155 style Ethereum transaction signing  
   - **`GetSharedSecret(...)`**: Shared key derivation for encryption  
   - **`EncryptWithHash(...)` and `DecryptMessage(...)`**: AES‐GCM encryption/decryption methods  

2. **`hdderive.go`**  
   Implements HD wallet operations:
   - **`InitHDMaster(...)`**: Initializes the master HD key from the signer's private key  
   - **`DeriveHDKey(...)`**: Accepts a derivation path string (e.g. `m/44'/60'/0'/0/1`) and derives a new child key  
   - **`DeriveEthereumHDKey(...)`**: Similar functionality using a `go-ethereum` derivation path object  

3. **`hdproof.go`**  
   Demonstrates the proof of parent–child relationship:
   - **`ProveHDRelation(...)`**: Signs a child’s public key bytes using the parent’s private key  
   - **`VerifyHDRelation(...)`**: Recovers the signing public key and verifies it matches the parent’s  

4. **`main.go`**  
   Serves as a runnable example:
   - Generates a random parent private key  
   - Creates an HD master key and derives multiple child keys  
   - Proves and verifies each child’s derivation relationship with the parent  

---

## Usage

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/raadhshenshahhaseeb/encode-zkml-project
   cd encode-zkml-project
   ```

2. **Install Dependencies**  
   Ensure Go is installed on your system. Then run:
   ```bash
   go mod tidy
   ```

3. **Run the Example**  
   ```bash
   go run cmd/main.go
   ```
   You will see console output indicating the parent private key, child derivation paths, and verification results.

---

## Technical Details

- **HD Key Derivation**  
  This project utilizes `btcsuite`’s `hdkeychain` package to derive child keys from a master key. Indices within the path may be hardened (e.g., `0x80000000` added) or unhardened.  
- **ECDSA and Ethereum**  
  The parent–child proof relies on Ethereum’s signature scheme. `crypto.Ecrecover` is used to recover the public key from a signature and compare it to the parent’s known public key.  
- **Raw vs. Full Ethereum Signature**  
  The code distinguishes between raw ECDSA `(r, s)` signatures and Ethereum‐style `(r, s, v)`. In functions such as `ProveHDRelation`, the resulting signature includes `v` for public key recovery.

---

## Security Notice

- **Key Exposure**: The example code prints private keys for demonstration. In a real‐world application, never log or expose private keys.  
- **Production Readiness**: This demonstration does not include secure storage, hardware wallet integration, or comprehensive error handling. For a production environment, additional safeguards are required.  
- **Entropy**: When creating a new key (`NewKey()`), the code depends on `crypto.GenerateKey()` from Go’s standard library, which is sufficiently secure for most use cases but should still be handled carefully.

---

## License

All files are provided under the terms of the [MIT License](https://opensource.org/licenses/MIT). See the `LICENSE` file for details. 

---

**Disclaimer:** Use this repository at your own risk. While it may serve as a valuable learning tool, it is not audited or officially supported for handling significant funds or sensitive operations. AI was used to generate portions of the code.