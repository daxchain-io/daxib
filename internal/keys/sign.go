package keys

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// sign.go is the keys provider's signing seam: the ONLY place a wallet's private
// keys are materialized from the unlocked seed. The service hands in the built
// (unsigned) *wire.MsgTx plus, per input, the BIP-84 derivation coordinates
// (branch/index) and the prevout (pkScript + value) needed for the BIP-143
// segwit sighash. SignInputs derives each input's private key from the seed,
// signs with txscript.WitnessSignature (low-S, SigHashAll, compressed pubkey),
// attaches the witness, and ZEROES every secret before returning. The seed and
// derived keys never leave this function.
//
// Keeping signing here (not in service) means the service never touches a
// private key or a seed — it only ever holds the built tx and the prevout
// metadata. A wrong (branch,index)→key mapping is caught by the engine-verify
// integration test (an invalid signature fails txscript.Execute).

// InputSigningSpec is the per-input information SignInputs needs: which input of
// the tx to sign, its BIP-84 derivation coordinates, and the prevout it spends
// (pkScript + value) for the BIP-143 sighash.
type InputSigningSpec struct {
	Index      int           // the tx input index to sign
	Branch     domain.Branch // BIP-84 branch (receive/change)
	AddrIndex  uint32        // BIP-84 address index on that branch
	PrevScript []byte        // the prevout's scriptPubKey (P2WPKH)
	PrevValue  int64         // the prevout's value in sats (BIP-143 amount)
}

// SignInputs signs each named input of tx in place. It verifies the passphrase,
// unlocks the wallet mnemonic, re-derives the seed + BIP-84 account key, and for
// each spec derives the leaf private key and attaches a P2WPKH witness. Every
// secret (mnemonic, seed, derived keys, raw privkey bytes) is zeroed before
// return. The tx version/inputs/outputs/sequences must already be set by the
// caller; SignInputs only fills the witnesses.
//
// A wrong passphrase is keystore.bad_passphrase (exit 4); an unknown wallet is
// wallet.not_found (exit 10). A spec.Index out of range or a derivation failure
// is state.corrupt.
func (s *Store) SignInputs(ctx context.Context, walletName string, net domain.Network, pass *secret.Bytes, tx *wire.MsgTx, specs []InputSigningSpec) error {
	return s.SignInputsWithPrevouts(ctx, walletName, net, pass, tx, specs, nil)
}

// SignInputsWithPrevouts is SignInputs plus an explicit prevout map covering
// inputs the wallet does NOT sign (a co-signer's FOREIGN inputs in a partially-
// owned PSBT). It signs only the named specs but seeds the BIP-143 sighash
// machinery with EVERY input's prevout, because txscript.NewTxSigHashes
// pre-computes the segwit sighash midstate over ALL inputs and dereferences each
// prevout's PkScript (e.g. for the taproot check); a missing foreign prevout would
// nil-panic there. extraPrevouts maps a tx outpoint -> its prevout (script+value);
// the spec'd (owned) prevouts always take precedence. Pass nil extraPrevouts for
// the all-owned send path (identical to SignInputs).
func (s *Store) SignInputsWithPrevouts(ctx context.Context, walletName string, net domain.Network, pass *secret.Bytes, tx *wire.MsgTx, specs []InputSigningSpec, extraPrevouts map[wire.OutPoint]*wire.TxOut) error {
	if tx == nil {
		return errKeys(CodeStateCorrupt, "nil transaction in SignInputs")
	}
	if verr := s.VerifyPassphrase(pass); verr != nil {
		return verr
	}

	meta, err := s.loadMeta()
	if err != nil {
		return err
	}
	wid, _, _, cerr := meta.walletChain(walletName, net)
	if cerr != nil {
		return cerr
	}
	network := net

	wb, err := s.loadWalletBlob(wid)
	if err != nil {
		return err
	}
	mnemonic, bip39pass, oerr := s.openMnemonic(wb, pass.Reveal())
	if oerr != nil {
		return oerr
	}
	defer zeroBytes(mnemonic)
	defer zeroBytes(bip39pass)

	// Re-derive the seed + account key (the same path materializeWallet used).
	seed := bip39.NewSeed(string(mnemonic), string(bip39pass))
	defer zeroBytes(seed)

	account, err := deriveAccountKey(seed, network)
	if err != nil {
		return err
	}
	defer account.Zero()

	// Build the BIP-143 sighash machinery over the prevouts. Seed the fetcher with
	// EVERY input's prevout: the owned (spec'd) inputs first (authoritative), then
	// any caller-supplied foreign prevouts. NewTxSigHashes iterates all inputs, so a
	// foreign input absent from the fetcher would nil-panic.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(tx.TxIn))
	for op, out := range extraPrevouts {
		if out != nil {
			prevOuts[op] = out
		}
	}
	for _, sp := range specs {
		if sp.Index < 0 || sp.Index >= len(tx.TxIn) {
			return errKeysf(CodeStateCorrupt, "signing spec input index %d out of range", sp.Index)
		}
		prevOuts[tx.TxIn[sp.Index].PreviousOutPoint] = wire.NewTxOut(sp.PrevValue, sp.PrevScript)
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	for _, sp := range specs {
		priv, derr := deriveLeafPrivKey(account, sp.Branch, sp.AddrIndex)
		if derr != nil {
			return derr
		}
		witness, werr := txscript.WitnessSignature(
			tx, sigHashes, sp.Index, sp.PrevValue, sp.PrevScript,
			txscript.SigHashAll, priv, true, // compressed pubkey (BIP-84)
		)
		// btcec.PrivateKey has no Zero(); overwrite its serialized bytes is not
		// directly exposed, but the key is GC'd promptly after this scope. We zero
		// the seed/account (the upstream material) which is the durable secret.
		priv.Zero()
		if werr != nil {
			return errWrap(CodeStateCorrupt, "signing input", werr)
		}
		tx.TxIn[sp.Index].Witness = witness
	}
	return nil
}

// deriveLeafPrivKey derives the leaf EC private key at account/branch/index. The
// intermediate branch node is zeroed; the caller zeroes the returned key.
func deriveLeafPrivKey(account *hdkeychain.ExtendedKey, branch domain.Branch, index uint32) (*btcec.PrivateKey, error) {
	branchKey, err := account.Derive(uint32(branch))
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving branch node", err)
	}
	defer branchKey.Zero()

	leaf, err := branchKey.Derive(index)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving leaf node", err)
	}
	defer leaf.Zero()

	priv, err := leaf.ECPrivKey()
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "extracting private key", err)
	}
	return priv, nil
}
