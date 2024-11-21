package btc

import (
	"errors"
)

func VerifyBitcoinSignature(btcAddress string, signature []byte, message string) (bool, error) {
	// Decode Bitcoin address
	address, addressType, err := decodeBitcoinAddress(btcAddress)
	if err != nil {
		return false, err
	}
	switch addressType {
	case "p2sh":
		return verifyP2SHSignature(address, signature, message)
	case "p2tr":
		return verifyP2TRSignature(address, signature, message)
	}
	return false, errors.New("failed signature verification")
}
