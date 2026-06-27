package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
)

// WalletCreateInput carries the frontend secret-source flags for `wallet create`.
type WalletCreateInput struct {
	PassphraseStdin bool
	PassphraseFile  string
	ConfirmStdin    bool
	ConfirmFile     string
}

// WalletImportInput carries the frontend secret-source flags for `wallet import`.
type WalletImportInput struct {
	MnemonicStdin   bool
	MnemonicFile    string
	BIP39Stdin      bool
	BIP39File       string
	PassphraseStdin bool
	PassphraseFile  string
	ConfirmStdin    bool
	ConfirmFile     string
}

// WalletExportInput carries the frontend secret-source flags for `wallet export`.
type WalletExportInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// WalletUpgradeInput carries the frontend secret-source flags for `wallet upgrade`.
type WalletUpgradeInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// WalletCreate generates a fresh mnemonic, encrypts it, derives the first receive
// address, and returns the once-only mnemonic in the result (Sensitive=true). The
// keystore passphrase is verified (or, on first init, confirmed) first.
func (s *Service) WalletCreate(ctx context.Context, req domain.WalletCreateRequest, in WalletCreateInput) (domain.WalletCreateResult, error) {
	network, err := s.walletNetwork(req.Network)
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	// A --bind create LOCKS the wallet to one network, so it REQUIRES a resolved
	// network (no silent default). An agnostic create (no --bind) may proceed with
	// network == "" — it materializes both coin_type chains and renders no
	// per-network sample address.
	if req.Bind && network == "" {
		return domain.WalletCreateResult{}, s.requireNetwork()
	}

	pass, _, err := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	defer pass.Zero()

	confirm, err := s.acquireConfirm(confirmSpec(in.ConfirmStdin, in.ConfirmFile, in.PassphraseStdin))
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	defer confirm.Zero()

	res, err := s.keys.CreateWallet(ctx, req.Name, req.Words, network, req.Bind, pass, confirm)
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	defer res.Mnemonic.Zero()
	defer res.BIP39Pass.Zero()

	out := domain.WalletCreateResult{
		Name:            req.Name,
		WalletID:        res.WalletID,
		Scope:           res.Scope,
		Network:         res.Network,
		PathPrefix:      res.PathPrefix,
		Receive0Address: res.Receive0Address,
		AccountXpub:     res.AccountXpub,
		Mnemonic:        string(res.Mnemonic.Reveal()),
		Sensitive:       true,
	}
	// Only surface the 0/0 receive ref when a per-network sample address was rendered
	// (an agnostic create with no resolved network has no display address — see
	// keys.materializeWallet — and we render no receive line for it).
	if res.Receive0Address != "" {
		out.Receive0 = req.Name + "/0/0"
	}
	if res.BIP39Pass != nil && res.BIP39Pass.Len() > 0 {
		out.BIP39Passphrase = string(res.BIP39Pass.Reveal())
	}
	return out, nil
}

// WalletImport ingests an existing mnemonic (stdin/file only) with an optional
// BIP-39 passphrase, checksum-validating it. The keystore passphrase is verified
// (or confirmed on first init) first.
func (s *Service) WalletImport(ctx context.Context, req domain.WalletImportRequest, in WalletImportInput) (domain.WalletImportResult, error) {
	network, err := s.walletNetwork(req.Network)
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	// A --bind import LOCKS the wallet to one network, so it REQUIRES a resolved
	// network (no silent default). An agnostic import may proceed with network == "".
	if req.Bind && network == "" {
		return domain.WalletImportResult{}, s.requireNetwork()
	}

	stdinTaken := in.MnemonicStdin
	mnemonic, _, err := s.acquire(secretSpec{
		StdinFlag:    in.MnemonicStdin,
		FilePath:     in.MnemonicFile,
		PromptLabel:  "BIP-39 mnemonic: ",
		RequiredCode: domain.CodeMnemonicRequired,
	})
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer mnemonic.Zero()

	bip39, _, err := s.acquireOptional(secretSpec{
		StdinFlag:   in.BIP39Stdin,
		FilePath:    in.BIP39File,
		PromptLabel: "BIP-39 passphrase (25th word, blank if none): ",
		StdinTaken:  stdinTaken,
	})
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer bip39.Zero()
	if in.BIP39Stdin {
		stdinTaken = true
	}

	pass, _, err := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, stdinTaken))
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer pass.Zero()
	if in.PassphraseStdin {
		stdinTaken = true
	}

	confirm, err := s.acquireConfirm(confirmSpec(in.ConfirmStdin, in.ConfirmFile, stdinTaken))
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer confirm.Zero()

	res, err := s.keys.ImportWallet(ctx, req.Name, network, req.Bind, mnemonic, bip39, pass, confirm)
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer res.BIP39Pass.Zero()

	out := domain.WalletImportResult{
		Name:            req.Name,
		WalletID:        res.WalletID,
		Scope:           res.Scope,
		Network:         res.Network,
		PathPrefix:      res.PathPrefix,
		Receive0Address: res.Receive0Address,
		AccountXpub:     res.AccountXpub,
	}
	// Only surface the 0/0 receive ref when a per-network sample address exists (an
	// agnostic import with no resolved network has none).
	if res.Receive0Address != "" {
		out.Receive0 = req.Name + "/0/0"
	}
	return out, nil
}

// WalletList returns every wallet's summary.
func (s *Service) WalletList(ctx context.Context, _ domain.WalletListRequest) (domain.WalletListResult, error) {
	// wallet list renders each wallet's sample address PER NETWORK, so it requires a
	// resolved network (no silent default).
	if err := s.requireNetwork(); err != nil {
		return domain.WalletListResult{}, err
	}
	wallets, err := s.keys.ListWallets(ctx, s.net)
	if err != nil {
		return domain.WalletListResult{}, err
	}
	out := domain.WalletListResult{Wallets: make([]domain.WalletSummary, 0, len(wallets))}
	for _, w := range wallets {
		if w.Default {
			out.Default = w.Name
		}
		out.Wallets = append(out.Wallets, domain.WalletSummary{
			Name:      w.Name,
			WalletID:  w.ID,
			Scope:     w.Scope,
			Network:   w.Network,
			CoinType:  w.CoinType,
			Addresses: w.Addresses,
			Default:   w.Default,
			CreatedAt: w.CreatedAt,
		})
	}
	return out, nil
}

// WalletShow returns one wallet's detail.
func (s *Service) WalletShow(ctx context.Context, req domain.WalletShowRequest) (domain.WalletShowResult, error) {
	// wallet show renders per-network (sample addresses, next-index addresses), so it
	// requires a resolved network (no silent default).
	if err := s.requireNetwork(); err != nil {
		return domain.WalletShowResult{}, err
	}
	w, err := s.keys.ShowWallet(ctx, req.Name, s.net)
	if err != nil {
		return domain.WalletShowResult{}, err
	}
	return domain.WalletShowResult{
		Name:        w.Name,
		WalletID:    w.ID,
		Scope:       w.Scope,
		Network:     w.Network,
		CoinType:    w.CoinType,
		PathPrefix:  w.PathPrefix,
		AccountXpub: w.AccountXpub,
		NextReceive: w.NextReceive,
		NextChange:  w.NextChange,
		Addresses:   w.Addresses,
		Default:     w.Default,
		CreatedAt:   w.CreatedAt,
	}, nil
}

// WalletUpgrade promotes a bound/legacy wallet to network-agnostic: it derives the
// missing coin_type chain from the seed (one-time passphrase) so the wallet then
// works on every network. An already-agnostic wallet is usage.already_agnostic.
func (s *Service) WalletUpgrade(ctx context.Context, req domain.WalletUpgradeRequest, in WalletUpgradeInput) (domain.WalletUpgradeResult, error) {
	pass, _, err := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.WalletUpgradeResult{}, err
	}
	defer pass.Zero()

	w, err := s.keys.WalletUpgrade(ctx, req.Name, s.net, pass)
	if err != nil {
		return domain.WalletUpgradeResult{}, err
	}
	return domain.WalletUpgradeResult{
		Name:      w.Name,
		WalletID:  w.ID,
		Scope:     w.Scope,
		Network:   w.Network,
		CoinType:  w.CoinType,
		Addresses: w.Addresses,
	}, nil
}

// WalletExport decrypts and returns a wallet's mnemonic + bip39 passphrase
// (operator-only; needs the passphrase).
func (s *Service) WalletExport(ctx context.Context, req domain.WalletExportRequest, in WalletExportInput) (domain.WalletExportResult, error) {
	pass, _, err := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.WalletExportResult{}, err
	}
	defer pass.Zero()

	id, mnemonic, bip39, err := s.keys.ExportWallet(ctx, req.Name, pass)
	if err != nil {
		return domain.WalletExportResult{}, err
	}
	defer mnemonic.Zero()
	defer bip39.Zero()

	out := domain.WalletExportResult{
		Name:      req.Name,
		WalletID:  id,
		Mnemonic:  string(mnemonic.Reveal()),
		Sensitive: true,
	}
	if bip39 != nil && bip39.Len() > 0 {
		out.BIP39Passphrase = string(bip39.Reveal())
	}
	return out, nil
}

// walletNetwork resolves the network for a wallet operation: the request's
// network (already parsed by the cli from --network), falling back to the
// service's active network.
func (s *Service) walletNetwork(reqNet domain.Network) (domain.Network, error) {
	if reqNet != "" {
		return reqNet, nil
	}
	return s.net, nil
}
