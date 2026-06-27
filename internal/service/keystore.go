package service

import (
	"context"
	"crypto/subtle"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// keystore.go holds the operator-only keystore-maintenance use cases:
// change-passphrase (the §3.8-parity atomic two-phase re-encryption) and info.
// Both are CLI-only — there is NO MCP tool for them (an agent never rotates or
// re-encrypts the keystore).

// New-passphrase env channels (independent of the keystore-unlock channel so the
// OLD and NEW passphrases never collide on the same source).
const (
	envNewPassphrase         = "DAXIB_NEW_PASSPHRASE"              //nolint:gosec // G101: env var NAME, not a credential
	envNewPassphraseFile     = "DAXIB_NEW_PASSPHRASE_FILE"         //nolint:gosec // G101: env var NAME, not a credential
	envNewPassphraseConfirm  = "DAXIB_NEW_PASSPHRASE_CONFIRM"      //nolint:gosec // G101: env var NAME, not a credential
	envNewPassphraseConfFile = "DAXIB_NEW_PASSPHRASE_CONFIRM_FILE" //nolint:gosec // G101: env var NAME, not a credential
)

// KeystoreChangePassphraseInput carries the OLD + NEW passphrase channels. The old
// uses the standard --passphrase-* channel; the new its own --new-passphrase-*
// channel + DAXIB_NEW_PASSPHRASE[_FILE]. Both are freshly resolved and zeroed.
type KeystoreChangePassphraseInput struct {
	OldStdin bool
	OldFile  string

	NewStdin bool
	NewFile  string

	// NewConfirm* feed the MANDATORY new-passphrase double-entry, so a rotation can
	// never land on a typo'd new passphrase (which would re-encrypt the WHOLE
	// keystore onto an unreproducible value — permanent lockout). Optional when a
	// --new-passphrase-stdin|file source is explicit AND a confirm channel is given;
	// otherwise resolved interactively or it fails closed.
	NewConfirmStdin bool
	NewConfirmFile  string
}

// KeystoreChangePassphrase re-encrypts the verifier + every wallet blob under a NEW
// passphrase, atomically (§3.8): a crash leaves either the all-old or the all-new
// keystore, never a mix. keys.Open already healed any prior crashed rotation
// (forward/back) before this runs.
func (s *Service) KeystoreChangePassphrase(ctx context.Context, req domain.KeystoreChangePassphraseRequest, in KeystoreChangePassphraseInput) (domain.KeystoreChangePassphraseResult, error) {
	_ = req // Yes is the cli confirmation gate; no payload here.

	oldPass, _, err := s.acquire(passphraseSpec(in.OldStdin, in.OldFile, false))
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	defer oldPass.Zero()

	stdinTaken := in.OldStdin
	newPass, _, err := s.acquire(secretSpec{
		StdinFlag:    in.NewStdin,
		FilePath:     in.NewFile,
		EnvVar:       envNewPassphrase,
		EnvFileVar:   envNewPassphraseFile,
		PromptLabel:  "New keystore passphrase: ",
		RequiredCode: "keystore.passphrase_required",
		StdinTaken:   stdinTaken,
	})
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	defer newPass.Zero()
	if in.NewStdin {
		stdinTaken = true
	}

	// The new-passphrase confirmation is MANDATORY (first-init parity): a typo would
	// silently re-encrypt the entire keystore onto an unconfirmed value and the OLD
	// passphrase stops working after commit. Fail CLOSED with keystore.confirm_required
	// when no confirm channel and no TTY exist — never a silent rotation, never a hang.
	confirm, cerr := s.acquireRotationConfirm(in, stdinTaken)
	if cerr != nil {
		return domain.KeystoreChangePassphraseResult{}, cerr
	}
	defer confirm.Zero()
	if subtle.ConstantTimeCompare(newPass.Reveal(), confirm.Reveal()) != 1 {
		return domain.KeystoreChangePassphraseResult{}, domain.New(
			"keystore.confirm_required",
			"the new passphrase and its confirmation do not match",
		)
	}

	rotated, err := s.keys.ChangePassphrase(ctx, oldPass, newPass)
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	return domain.KeystoreChangePassphraseResult{RotatedFiles: rotated}, nil
}

// acquireRotationConfirm resolves the MANDATORY new-passphrase confirmation,
// mirroring first-init's fail-closed contract:
//
//   - an explicit confirm channel present → acquire it;
//   - no explicit channel, at a TTY → a real second prompt (double-entry);
//   - no explicit channel, no TTY → keystore.confirm_required (never a silent
//     rotation onto a possibly typo'd passphrase, never a hang).
func (s *Service) acquireRotationConfirm(in KeystoreChangePassphraseInput, stdinTaken bool) (*secret.Bytes, error) {
	spec := secretSpec{
		StdinFlag:   in.NewConfirmStdin,
		FilePath:    in.NewConfirmFile,
		EnvVar:      envNewPassphraseConfirm,
		EnvFileVar:  envNewPassphraseConfFile,
		PromptLabel: "Confirm new keystore passphrase: ",
		StdinTaken:  stdinTaken,
	}
	if s.specHasExplicit(spec) {
		c, _, cerr := s.acquire(spec)
		return c, cerr
	}
	if s.secret.IsTTY != nil && s.secret.IsTTY() {
		c, _, cerr := s.acquire(spec)
		return c, cerr
	}
	return nil, domain.New(
		"keystore.confirm_required",
		"changing the keystore passphrase requires confirming the new passphrase: "+
			"supply --new-passphrase-confirm-stdin|file or DAXIB_NEW_PASSPHRASE_CONFIRM[_FILE] "+
			"(or run interactively for double-entry); refusing to rotate without a confirmation",
	)
}

// KeystoreInfo reports the keystore path, manifest format, KDF template, and wallet
// count. Read-only; no unlock and no secret.
func (s *Service) KeystoreInfo(ctx context.Context, _ domain.KeystoreInfoRequest) (domain.KeystoreInfoResult, error) {
	info, err := s.keys.KeystoreInfo(ctx)
	if err != nil {
		return domain.KeystoreInfoResult{}, err
	}
	return domain.KeystoreInfoResult{
		Path:        info.Path,
		Format:      info.Format,
		Initialized: info.Initialized,
		Wallets:     info.Wallets,
		KDF:         info.KDF,
		ScryptN:     info.ScryptN,
	}, nil
}
