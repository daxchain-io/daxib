package service

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/daxchain-io/daxib/internal/bip322"
	"github.com/daxchain-io/daxib/internal/domain"
)

// message.go is the service's BIP-322 message sign/verify use cases. `sign` unlocks
// the address's key behind the keystore passphrase (the keys provider does the
// crypto); `verify` is passphrase-free (it routes straight to bip322.Verify). Both
// are P2WPKH-only (daxib's single address type, §3.5).

// MessageSignInput carries the frontend's message + passphrase channels for
// `sign message`. The message is NOT a secret (it travels by flag/file/stdin); the
// keystore passphrase uses the standard --passphrase-* channel.
type MessageSignInput struct {
	// Message is the resolved message bytes (the cli reads --message /
	// --message-file / --message-stdin and hands the bytes here).
	Message []byte

	PassphraseStdin bool
	PassphraseFile  string
}

// MessageSign signs req.Message for the address (or "<wallet>/<branch>/<index>"
// ref) in req.Ref using BIP-322 "simple". It resolves the ref to an address, then
// unlocks the address's key under the keystore passphrase and signs. The base64
// witness is the signature.
func (s *Service) MessageSign(ctx context.Context, req domain.MessageSignRequest, in MessageSignInput) (domain.MessageSignResult, error) {
	// sign message derives + renders the signing address PER NETWORK (and the bare-
	// address ref is resolved family-locally for s.net), so it requires a resolved
	// network. Guard first — before the wallet-scope check and ref resolution — so an
	// unqualified sign fails with usage.network_required, not a misleading not_found.
	if err := s.requireNetwork(); err != nil {
		return domain.MessageSignResult{}, err
	}
	// Gate sign message under the scope guard like every other key op, BEFORE
	// resolving the ref: a BOUND wallet refuses signing off its locked network
	// (usage.network_mismatch, exit 2), an AGNOSTIC wallet is unaffected. We must
	// run the guard first because resolveSignRef's <wallet>/<branch>/<index> path
	// derives via AddressAt, which on a bound wallet off its network has no chain
	// for the active coin_type and would fail with wallet.not_found (exit 10)
	// before the guard ever ran. Enforce it whenever the owning wallet is known (a
	// slash ref or an explicit --wallet hint); a bare address with no hint is
	// resolved family-locally by findAddress anyway.
	if hint := s.signRefWallet(req.Wallet, req.Ref); hint != "" {
		if aerr := s.assertWalletNetwork(ctx, hint); aerr != nil {
			return domain.MessageSignResult{}, aerr
		}
	}

	address, walletHint, err := s.resolveSignRef(ctx, req.Wallet, req.Ref)
	if err != nil {
		return domain.MessageSignResult{}, err
	}

	pass, _, err := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.MessageSignResult{}, err
	}
	defer pass.Zero()

	res, err := s.keys.SignMessage(ctx, walletHint, address, s.net, in.Message, pass)
	if err != nil {
		return domain.MessageSignResult{}, err
	}
	return domain.MessageSignResult{
		Address:   res.Address,
		Message:   string(in.Message),
		Signature: base64.StdEncoding.EncodeToString(res.Signature),
		Format:    bip322.Format,
	}, nil
}

// MessageVerify checks a base64 BIP-322 signature for (address, message). It is
// passphrase-free. A signature that DECODES but does not verify is NOT an error —
// it returns Valid=false with a nil error (exit 0), so an agent branches on the
// field. A malformed address or undecodable base64/witness is a usage error.
func (s *Service) MessageVerify(ctx context.Context, req domain.MessageVerifyRequest) (domain.MessageVerifyResult, error) {
	// verify validates the address AND interprets the BIP-322 witness PER NETWORK
	// (chainParams + bip322.Verify both key off s.net). With no network resolved
	// chainParams() would silently fall through to MainNetParams — a silent mainnet
	// default on an MCP-exposed tool. Guard FIRST so an unqualified verify fails with
	// usage.network_required (matching its sibling MessageSign), not a misleading
	// bad_address rendered against a defaulted network.
	if err := s.requireNetwork(); err != nil {
		return domain.MessageVerifyResult{}, err
	}
	if req.Address == "" {
		return domain.MessageVerifyResult{}, domain.New(domain.CodeUsageBadAddress, "--address is required for verify")
	}
	// Validate the address decodes for the active network before anything else.
	params := s.chainParams()
	if a, derr := btcutil.DecodeAddress(req.Address, params); derr != nil || !a.IsForNet(params) {
		return domain.MessageVerifyResult{}, domain.Newf(domain.CodeUsageBadAddress,
			"--address %q is not a valid %s address", req.Address, s.net)
	}

	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if derr != nil {
		return domain.MessageVerifyResult{}, domain.Newf(domain.CodeBadSignature,
			"--signature is not valid base64: %v", derr)
	}

	valid, verr := bip322.Verify(req.Address, []byte(req.Message), raw, s.net)
	if verr != nil {
		// A bip322 error here is a structurally malformed signature/address (not a
		// mere mismatch) — surface it as a usage failure.
		return domain.MessageVerifyResult{}, domain.Newf(domain.CodeBadSignature,
			"--signature is not a decodable BIP-322 witness: %v", verr)
	}
	return domain.MessageVerifyResult{
		Valid:     valid,
		Address:   req.Address,
		Message:   req.Message,
		Signature: req.Signature,
		Format:    bip322.Format,
	}, nil
}

// resolveSignRef turns a `sign` ref into a concrete P2WPKH address + an optional
// wallet hint (to scope the keystore lookup). The ref is either:
//
//   - a "<wallet>/<branch>/<index>" derivation ref (slash-delimited) — resolved to
//     its address via the keystore (no passphrase), with the wallet as the hint; or
//   - a raw bech32 address — used directly (the keystore finds its owning wallet).
//
// An explicit --wallet narrows a raw-address lookup. A malformed ref is a usage
// failure.
func (s *Service) resolveSignRef(ctx context.Context, walletFlag, ref string) (address, walletHint string, err error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", domain.New(domain.CodeUsageBadAddress, "a signing address or <wallet>/<branch>/<index> ref is required")
	}

	// A slash-delimited ref is "<wallet>/<branch>/<index>".
	if strings.Contains(ref, "/") {
		parts := strings.Split(ref, "/")
		if len(parts) != 3 {
			return "", "", domain.Newf(domain.CodeUsageBadAddress,
				"ref %q must be an address or <wallet>/<branch>/<index>", ref)
		}
		walletName := parts[0]
		branch, ok := parseBranch(parts[1])
		if !ok {
			return "", "", domain.Newf(domain.CodeUsageBadAddress, "ref %q has a bad branch (want 0 or 1)", ref)
		}
		index, ok := parseIndex(parts[2])
		if !ok {
			return "", "", domain.Newf(domain.CodeUsageBadAddress, "ref %q has a bad index", ref)
		}
		d, derr := s.keys.AddressAt(ctx, walletName, s.net, branch, index)
		if derr != nil {
			return "", "", derr
		}
		return d.Address, walletName, nil
	}

	// Otherwise it is a raw address. Validate it decodes for the active network.
	params := s.chainParams()
	if a, derr := btcutil.DecodeAddress(ref, params); derr != nil || !a.IsForNet(params) {
		return "", "", domain.Newf(domain.CodeUsageBadAddress,
			"%q is not a valid %s address (or a <wallet>/<branch>/<index> ref)", ref, s.net)
	}
	hint := walletFlag
	if hint == "" {
		hint = s.wallet
	}
	return ref, hint, nil
}

// signRefWallet returns the wallet name a `sign` ref will be scoped to, WITHOUT
// touching any derivation chain — so MessageSign can run the scope guard before
// resolveSignRef derives. It mirrors resolveSignRef's hint logic: a slash ref
// "<wallet>/<branch>/<index>" yields its leading wallet name; a bare address
// yields the explicit --wallet flag, else the session default wallet. It returns
// "" when no owning wallet is determinable (a bare address with no hint), in
// which case the guard is skipped (findAddress resolves family-locally).
func (s *Service) signRefWallet(walletFlag, ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.Contains(ref, "/") {
		parts := strings.Split(ref, "/")
		if len(parts) == 3 && parts[0] != "" {
			return parts[0]
		}
		return ""
	}
	if walletFlag != "" {
		return walletFlag
	}
	return s.wallet
}

// parseBranch parses a "0"/"1" branch token.
func parseBranch(s string) (domain.Branch, bool) {
	switch s {
	case "0":
		return domain.BranchReceive, true
	case "1":
		return domain.BranchChange, true
	default:
		return 0, false
	}
}

// parseIndex parses a non-negative decimal derivation index (no leading zeros
// beyond a lone "0").
func parseIndex(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return uint32(v), true
}
