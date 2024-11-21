package btc

import (
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func decodeBitcoinAddress(btcAddress string) (btcutil.Address, string, error) {
	// Decode the address
	address, err := btcutil.DecodeAddress(btcAddress, &chaincfg.MainNetParams)
	if err != nil {
		return nil, "", errors.New("could not decode address")
	}
	switch address.(type) {
	// Validate P2SH
	case *btcutil.AddressScriptHash:
		return address, "p2sh", nil
	// Validate P2TR
	case *btcutil.AddressTaproot:
		return address, "p2tr", nil
	// Unsupported address
	default:
		return nil, "", errors.New("address format not supported")
	}
}
