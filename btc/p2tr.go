package btc

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Verify ensures that the signature for the message hash is valid for the public key given.
func verifyP2TRSignature(address btcutil.Address, signatureBytes []byte, message string) (bool, error) {
	// Convert address into corresponding script pubkey
	scriptPubKey, err := getPkScriptByAddress(address)
	// fmt.Println("scriptPubKey", scriptPubKey)

	if err != nil {
		return false, err
	}
	// Add the witness stack into the toSignTx
	var witness wire.TxWitness
	if len(signatureBytes) == 66 && signatureBytes[0] == 1 && signatureBytes[1] == 64 {
		witness = wire.TxWitness{signatureBytes[2:]}
	} else {
		return false, errors.New("b64 signature invalid for taproot")
	}
	// Draft corresponding toSpend and toSign transaction using the message and script pubkey
	toSpendTx, err := buildToSpendTx(message, scriptPubKey)
	if err != nil {
		return false, err
	}
	toSignTx, err := buildToSignTx(toSpendTx.TxHash())
	if err != nil {
		return false, err
	}
	toSignTx.TxIn[0].Witness = witness
	// fmt.Println("witness", witness)
	prevFetcher := txscript.NewCannedPrevOutputFetcher(scriptPubKey, 0)
	hashCache := txscript.NewTxSigHashes(toSignTx, prevFetcher)
	// fmt.Println("hashCache", hashCache)
	vm, err := txscript.NewEngine(scriptPubKey, toSignTx, 0, txscript.StandardVerifyFlags, nil, hashCache, 0, prevFetcher)
	if err != nil {
		return false, err
	}
	if err := vm.Execute(); err != nil {
		return false, fmt.Errorf("signature verification failed %v", err)
	}
	return true, nil
}

/**
 * Build a to_spend transaction using simple signature in accordance to the BIP-322.
 * @param message Message to be signed using BIP-322
 * @param scriptPublicKey The script public key for the signing wallet
 * @returns Bitcoin transaction that correspond to the to_spend transaction
 */
func buildToSpendTx(message string, scriptPubKey []byte) (*wire.MsgTx, error) {
	psbt := wire.NewMsgTx(0)
	// Decode the message hash
	messageHash := getTagSha256([]byte(message))
	fmt.Println("messageHash", messageHash)
	// Create the script for to_spend
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(messageHash)
	scriptSig, err := builder.Script()
	if err != nil {
		return nil, err
	}
	// Set the input
	prevOutHash, err := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000") // Create a TxIn with the outpoint 000...000:FFFFFFFF
	if err != nil {
		return nil, err
	}
	prevOut := wire.NewOutPoint(prevOutHash, wire.MaxPrevOutIndex)
	txIn := wire.NewTxIn(prevOut, scriptSig, nil)
	txIn.Sequence = 0
	psbt.AddTxIn(txIn)
	//Set the output
	psbt.AddTxOut(wire.NewTxOut(0, scriptPubKey))
	//return
	return psbt, nil
}

/**
 * Build a to_sign transaction using simple signature in accordance to the BIP-322.
 * @param toSpendTxId Transaction ID of the to_spend transaction as constructed by buildToSpendTx
 * @param witnessScript The script public key for the signing wallet, or the redeemScript for P2SH-P2WPKH address
 * @param isRedeemScript Set to true if the provided witnessScript is a redeemScript for P2SH-P2WPKH address, default to false
 * @param tapInternalKey Used to set the taproot internal public key of a taproot signing address when provided, default to undefined
 * @returns Ready-to-be-signed bitcoinjs.Psbt transaction
 */
func buildToSignTx(toSpendTxId chainhash.Hash) (*wire.MsgTx, error) {
	psbt := wire.NewMsgTx(0)
	// Set the input
	prevOutSpend := wire.NewOutPoint((*chainhash.Hash)(toSpendTxId.CloneBytes()), 0)
	txIn := wire.NewTxIn(prevOutSpend, nil, nil)
	txIn.Sequence = 0
	psbt.AddTxIn(txIn)
	// Create the script for to_sign
	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddOp(txscript.OP_RETURN)
	scriptPk, err := scriptBuilder.Script()
	if err != nil {
		return nil, err
	}
	//Set the output
	psbt.AddTxOut(wire.NewTxOut(0, scriptPk))
	//return
	return psbt, nil
}

func getPkScriptByAddress(address btcutil.Address) (pk []byte, err error) {
	addressPkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		return nil, err
	}
	return addressPkScript, nil
}

func getTagSha256(data []byte) (hash []byte) {
	tag := []byte("BIP0322-signed-message")
	hashTag := getSha256(tag)
	var msg []byte
	msg = append(msg, hashTag...)
	msg = append(msg, hashTag...)
	msg = append(msg, data...)
	return getSha256(msg)
}

func getSha256(data []byte) (hash []byte) {
	sha := sha256.New()
	sha.Write(data[:])
	hash = sha.Sum(nil)
	return
}
