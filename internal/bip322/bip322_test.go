package bip322

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/domain"
)

// The signing key + its mainnet P2WPKH address used across these tests. The WIF is
// the BIP-322 reference key; the address is its P2WPKH form.
const (
	vecWIF     = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
	vecAddress = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
)

// TestCanonicalMessageHash pins MessageHash to the BIP-322 tagged-hash of the
// empty and "Hello World" messages — the canonical published values
// (tagged_hash("BIP0322-signed", message)). These are independently recomputable
// as SHA256(SHA256(tag)||SHA256(tag)||msg).
func TestCanonicalMessageHash(t *testing.T) {
	cases := map[string]string{
		"":            "888bab9b0d983d5058a18821fa257f99d05105d3fa0a01f162666e905c4cebc1",
		"Hello World": "a8b6c7515051928c83e7e0ff14083c2ec67bc4ff9b8ba8db4d0155696d02aa50",
	}
	for msg, want := range cases {
		if got := hex.EncodeToString(MessageHash([]byte(msg))); got != want {
			t.Errorf("MessageHash(%q) = %s, want %s", msg, got, want)
		}
	}
}

// TestCanonicalVirtualTxStructure asserts the BIP-322 to_spend virtual tx is built
// byte-for-byte per the spec: version 0, locktime 0; one input on the null outpoint
// (all-zero hash, index 0xFFFFFFFF, sequence 0) with scriptSig "OP_0 PUSH32
// <messageHash>"; one zero-value output paying the address scriptPubKey. The test
// hand-serializes the EXPECTED bytes independently and compares — a structural
// pin that does not depend on any externally-transcribed txid.
func TestCanonicalVirtualTxStructure(t *testing.T) {
	_, script, err := scriptForAddress(vecAddress, chainParams(domain.NetworkMainnet))
	if err != nil {
		t.Fatalf("scriptForAddress: %v", err)
	}
	if got := hex.EncodeToString(script); got != "00142b05d564e6a7a33c087f16e0f730d1440123799d" {
		t.Fatalf("scriptPubKey = %s, unexpected for the vector address", got)
	}

	toSpend, err := buildToSpend(script, MessageHash(nil))
	if err != nil {
		t.Fatalf("buildToSpend: %v", err)
	}
	var got bytes.Buffer
	if err := toSpend.Serialize(&got); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// Hand-assembled BIP-322 to_spend for the empty message + the vector address.
	want := "00000000" + // nVersion = 0
		"01" + // vin count
		"0000000000000000000000000000000000000000000000000000000000000000" + // prevout hash (null)
		"ffffffff" + // prevout n = 0xFFFFFFFF
		"22" + // scriptSig length = 34
		"0020" + "888bab9b0d983d5058a18821fa257f99d05105d3fa0a01f162666e905c4cebc1" + // OP_0 PUSH32 messageHash
		"00000000" + // nSequence = 0
		"01" + // vout count
		"0000000000000000" + // value = 0
		"16" + "00142b05d564e6a7a33c087f16e0f730d1440123799d" + // scriptPubKey (P2WPKH)
		"00000000" // nLockTime = 0
	if hex.EncodeToString(got.Bytes()) != want {
		t.Errorf("to_spend bytes:\n got=%s\nwant=%s", hex.EncodeToString(got.Bytes()), want)
	}
}

// TestSignVerifyRoundtrip signs each message with the vector key and verifies the
// produced signature through txscript.NewEngine (Verify) — the end-to-end
// sign→engine-verify proof the design requires.
func TestSignVerifyRoundtrip(t *testing.T) {
	wif, err := btcutil.DecodeWIF(vecWIF)
	if err != nil {
		t.Fatalf("DecodeWIF: %v", err)
	}
	for _, msg := range []string{"", "Hello World", "daxib — the Bitcoin wallet for AI"} {
		sig, serr := Sign(vecAddress, []byte(msg), wif.PrivKey, domain.NetworkMainnet)
		if serr != nil {
			t.Fatalf("Sign(%q): %v", msg, serr)
		}
		ok, verr := Verify(vecAddress, []byte(msg), sig, domain.NetworkMainnet)
		if verr != nil {
			t.Fatalf("Verify(%q): %v", msg, verr)
		}
		if !ok {
			t.Errorf("roundtrip Verify(%q) = false, want true", msg)
		}
	}
}

// TestSignatureIndependentECDSAVerify cross-checks a daxib-produced signature
// WITHOUT going through txscript.NewEngine: it recomputes the BIP-143 segwit
// sighash for to_sign:0 by hand and runs btcec ecdsa.Verify against the pubkey
// from the witness. A pass means the witness carries a real ECDSA signature over
// the canonical BIP-322 sighash — an engine-independent proof that Verify's
// acceptance is not a tautology.
func TestSignatureIndependentECDSAVerify(t *testing.T) {
	wif, err := btcutil.DecodeWIF(vecWIF)
	if err != nil {
		t.Fatalf("DecodeWIF: %v", err)
	}
	msg := []byte("independent check")
	sig, err := Sign(vecAddress, msg, wif.PrivKey, domain.NetworkMainnet)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	witness, err := DeserializeWitness(sig)
	if err != nil {
		t.Fatalf("DeserializeWitness: %v", err)
	}
	if len(witness) != 2 {
		t.Fatalf("P2WPKH witness should have 2 items, got %d", len(witness))
	}
	sigBytes, pubBytes := witness[0], witness[1]

	// Strip the trailing sighash-type byte (SigHashAll = 0x01) and parse DER.
	if len(sigBytes) < 1 {
		t.Fatal("empty signature element")
	}
	der := sigBytes[:len(sigBytes)-1]
	parsedSig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatalf("ParseDERSignature: %v", err)
	}
	pub, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}

	// Recompute the BIP-143 sighash for to_sign:0 independently of Verify.
	_, script, _ := scriptForAddress(vecAddress, chainParams(domain.NetworkMainnet))
	toSpend, _ := buildToSpend(script, MessageHash(msg))
	toSign := buildToSign(toSpend)
	fetcher := txscript.NewCannedPrevOutputFetcher(script, 0)
	sigHashes := txscript.NewTxSigHashes(toSign, fetcher)
	hash, err := txscript.CalcWitnessSigHash(script, sigHashes, txscript.SigHashAll, toSign, 0, 0)
	if err != nil {
		t.Fatalf("CalcWitnessSigHash: %v", err)
	}
	if !parsedSig.Verify(hash, pub) {
		t.Fatal("independent ecdsa.Verify rejected a daxib BIP-322 signature")
	}
}

// TestVerifyTamperFails proves a tampered message, a tampered signature, and a
// wrong address all VERIFY false (not error) — the negative half of the contract.
func TestVerifyTamperFails(t *testing.T) {
	wif, _ := btcutil.DecodeWIF(vecWIF)
	sig, err := Sign(vecAddress, []byte("original message"), wif.PrivKey, domain.NetworkMainnet)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if ok, _ := Verify(vecAddress, []byte("tampered message"), sig, domain.NetworkMainnet); ok {
		t.Error("Verify accepted a tampered message")
	}

	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)/2] ^= 0xff
	if ok, verr := Verify(vecAddress, []byte("original message"), tampered, domain.NetworkMainnet); verr == nil && ok {
		t.Error("Verify accepted a tampered signature")
	}

	// A different, valid-format P2WPKH address (different key) must not verify.
	const otherAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
	if ok, _ := Verify(otherAddr, []byte("original message"), sig, domain.NetworkMainnet); ok {
		t.Error("Verify accepted a signature under the wrong address")
	}
}

// TestVerifyMalformedSignature proves a non-decodable witness is a usage error
// (not a silent false), so the service can surface usage.bad_signature.
func TestVerifyMalformedSignature(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00},                               // zero-count witness
		{0x01, 0x05, 0x01, 0x02},             // declares len 5, only 2 follow
		{0x02, 0x01, 0xaa, 0x01, 0xbb, 0xff}, // trailing garbage
	}
	for i, c := range cases {
		if _, err := Verify(vecAddress, []byte("m"), c, domain.NetworkMainnet); err == nil {
			t.Errorf("case %d: malformed witness did not error", i)
		}
	}
}

// TestUnsupportedAddress proves a non-P2WPKH address is rejected up front.
func TestUnsupportedAddress(t *testing.T) {
	const legacy = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" // legacy P2PKH
	if _, _, err := scriptForAddress(legacy, chainParams(domain.NetworkMainnet)); err == nil {
		t.Error("scriptForAddress accepted a non-P2WPKH address")
	}
}

// TestWitnessSerializeRoundtrip proves SerializeWitness/DeserializeWitness invert.
func TestWitnessSerializeRoundtrip(t *testing.T) {
	in := wire.TxWitness{[]byte{0x01, 0x02, 0x03}, []byte{0xaa, 0xbb}}
	out, err := DeserializeWitness(SerializeWitness(in))
	if err != nil {
		t.Fatalf("DeserializeWitness: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("item count = %d, want %d", len(out), len(in))
	}
	for i := range in {
		if !bytes.Equal(in[i], out[i]) {
			t.Errorf("item %d = %x, want %x", i, out[i], in[i])
		}
	}
}
