package btc

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/btc/flags"
	"github.com/samber/lo"
)

// varIntProtoVer is the protocol version to use for serializing N as a VarInt
// Copied from https://github.com/btcsuite/btcd/blob/v0.23.3/btcutil/gcs/gcs.go#L37
const varIntProtoVer uint32 = 0

// Signed message are prepended with this magicMessage
// Taken from https://bitcoin.stackexchange.com/a/77325
const magicMessage = "\x18Bitcoin Signed Message:\n"

// Values taken from `ecdsa`.
const (
	// compactSigSize is the size of a compact signature.  It consists of a
	// compact signature recovery code byte followed by the R and S components
	// serialized as 32-byte big-endian values. 1+32*2 = 65.
	// for the R and S components. 1+32+32=65.
	compactSigSize = 65

	// compactSigMagicOffset is a value used when creating the compact signature
	// recovery code inherited from Bitcoin and has no meaning, but has been
	// retained for compatibility.  For historical purposes, it was originally
	// picked to avoid a binary representation that would allow compact
	// signatures to be mistaken for other components.
	compactSigMagicOffset = 27

	// compactSigCompPubKey is a value used when creating the compact signature
	// recovery code to indicate the original public key was compressed.
	compactSigCompPubKey = 4
)

// Verify ensures that the signature for the message hash is valid for the public key given.
func verifyP2SHSignature(address btcutil.Address, signatureBytes []byte, message string) (bool, error) {
	// Ensure signature has proper length
	if len(signatureBytes) != 65 {
		return false, fmt.Errorf("wrong signature length: %d instead of 65", len(signatureBytes))
	}
	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureBytes[0])
	if !lo.Contains[int](flags.All(), recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}
	// Retrieve KeyID
	keyID := flags.GetKeyID(recoveryFlag)
	// Should address be compressed (for checking later)
	compressed := flags.ShouldBeCompressed(recoveryFlag)
	// Reset recovery flag after obtaining keyID for Trezor
	if lo.Contains[int](flags.Trezor(), recoveryFlag) {
		signatureBytes[0] = byte(27 + keyID)
	}
	// Make the magic message
	magicMessage, err := createMagicMessage(message)
	if err != nil {
		return false, err
	}
	// Hash the message
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))
	// Recover the public key from signature and message hash
	publicKey, comp, err := ecdsa.RecoverCompact(signatureBytes, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %w", err)
	}
	// Ensure our initial assumption was correct, except for Trezor as they do something different
	if compressed != comp && !lo.Contains[int](flags.Trezor(), recoveryFlag) {
		return false, errors.New("we expected the key to be compressed, it wasn't")
	}
	if publicKey == nil || !publicKey.IsOnCurve() {
		return false, errors.New("public key was not correctly instantiated")
	}
	// Parse the signature so we can verify it
	parsedSignature, err := parseCompact(signatureBytes)
	if err != nil {
		return false, err
	}
	// Actually verify the message
	if verified := parsedSignature.Verify(messageHash, publicKey); !verified {
		return false, errors.New("signature could not be verified")
	}
	// Get the hash from the public key, so we can check that address matches
	publicKeyHash := generatePublicKeyHash(recoveryFlag, publicKey)
	// Ensure proper address type will be generated
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return false, errors.New("cannot use P2SH for recovery flag 'P2PKH uncompressed'")
	} else if lo.Contains[int](flags.TrezorP2WPKH(), recoveryFlag) {
		return false, errors.New("cannot use P2SH for recovery flag 'BIP137 (Trezor) P2WPKH'")
	}
	// Generate the address and validate it
	if scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(publicKeyHash).Script(); err != nil {
		return false, err
	} else if p2shAddr, err := btcutil.NewAddressScriptHash(scriptSig, &chaincfg.MainNetParams); err != nil {
		return false, err
	} else if address.String() != p2shAddr.String() {
		return false, fmt.Errorf("generated address '%s' does not match expected address '%s'", p2shAddr.String(), address.String())
	}
	return true, nil
}

// CreateMagicMessage builds a properly signed message.
func createMagicMessage(message string) (string, error) {
	buffer := bytes.Buffer{}
	buffer.Grow(wire.VarIntSerializeSize(uint64(len(message))))
	// If we cannot write the VarInt, just panic since that should never happen
	if err := wire.WriteVarInt(&buffer, varIntProtoVer, uint64(len(message))); err != nil {
		return "", err
	}
	return magicMessage + buffer.String() + message, nil
}

// ParseCompact attempts to recover the ecdsa.Signature from the provided
// compact signature. The logic for this was taken from `ecdsa.RecoverCompact`
// as it is not exposed publicly.
func parseCompact(signature []byte) (*ecdsa.Signature, error) {
	// A compact signature consists of a recovery byte followed by the R and
	// S components serialized as 32-byte big-endian values.
	if len(signature) != compactSigSize {
		return nil, errors.New("invalid compact signature size")
	}
	// Parse and validate the compact signature recovery code.
	const (
		minValidCode = compactSigMagicOffset
		maxValidCode = compactSigMagicOffset + compactSigCompPubKey + 3
	)
	if signature[0] < minValidCode || signature[0] > maxValidCode {
		return nil, errors.New("invalid compact signature recovery code")
	}
	// Parse and validate the R and S signature components.
	// Fail if r and s are not in [1, N-1].
	var r, s btcec.ModNScalar
	if overflow := r.SetByteSlice(signature[1:33]); overflow {
		return nil, errors.New("signature R is >= curve order")
	}
	if r.IsZero() {
		return nil, errors.New("signature R is 0")
	}
	if overflow := s.SetByteSlice(signature[33:]); overflow {
		return nil, errors.New("signature S is >= curve order")
	}
	if s.IsZero() {
		return nil, errors.New("signature S is 0")
	}
	return ecdsa.NewSignature(&r, &s), nil
}

// GeneratePublicKeyHash returns the public key hash, either compressed or uncompressed, depending on the recovery flag.
func generatePublicKeyHash(recoveryFlag int, publicKey *btcec.PublicKey) []byte {
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return btcutil.Hash160(publicKey.SerializeUncompressed())
	}
	return btcutil.Hash160(publicKey.SerializeCompressed())
}
