package service

import (
	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/secret"
)

// Env var names for the §3.6 passphrase precedence (DAXIB_ namespace).
const (
	envPassphrase         = "DAXIB_PASSPHRASE"
	envPassphraseFile     = "DAXIB_PASSPHRASE_FILE"
	envPassphraseConfirm  = "DAXIB_PASSPHRASE_CONFIRM"
	envPassphraseConfFile = "DAXIB_PASSPHRASE_CONFIRM_FILE"
	// The ADMIN passphrase channels are INDEPENDENT of the keystore passphrase
	// (§3.7): distinct flag/env names and a distinct KDF (the anchor salt + admin
	// scrypt params), so a compromised agent holding the keystore passphrase gains
	// nothing toward forging a policy seal. The admin secret never arrives as a flag
	// value and is never set in an agent pod.
	envAdminPassphrase     = "DAXIB_ADMIN_PASSPHRASE"          //nolint:gosec // G101: env var NAME, not a credential
	envAdminPassphraseFile = "DAXIB_ADMIN_PASSPHRASE_FILE"     //nolint:gosec // G101: env var NAME, not a credential
	envAdminNewPassphrase  = "DAXIB_ADMIN_NEW_PASSPHRASE"      //nolint:gosec // G101: env var NAME, not a credential
	envAdminNewPassFile    = "DAXIB_ADMIN_NEW_PASSPHRASE_FILE" //nolint:gosec // G101: env var NAME, not a credential
)

// secretSpec describes one secret source set (the flag pair + stdin-taken state).
type secretSpec struct {
	StdinFlag    bool
	FilePath     string
	EnvVar       string
	EnvFileVar   string
	PromptLabel  string
	RequiredCode string
	StdinTaken   bool
}

// acquire resolves a secret through the §3.6 precedence (stdin > file > *_FILE-env
// > env > TTY prompt > deterministic error), injecting fsx.CheckPerms for file
// hygiene and the host SecretIO primitives. The returned *secret.Bytes is the
// caller's to zero.
func (s *Service) acquire(spec secretSpec) (*secret.Bytes, secret.Source, error) {
	req := secret.Request{
		StdinFlag:    spec.StdinFlag,
		FilePath:     spec.FilePath,
		EnvFileVar:   spec.EnvFileVar,
		EnvVar:       spec.EnvVar,
		PromptLabel:  spec.PromptLabel,
		RequiredCode: spec.RequiredCode,
		StdinTaken:   spec.StdinTaken,
		CheckFile:    fsx.CheckPerms,
		Prompt:       s.secret.Prompt,
	}
	return secret.Acquire(req, s.secret.Stdin, s.secret.LookupEnv, s.secret.IsTTY)
}

// acquireOptional resolves a secret only when an explicit source is present
// (used for the optional BIP-39 25th-word passphrase). With no explicit source it
// returns an empty secret and no prompt.
func (s *Service) acquireOptional(spec secretSpec) (*secret.Bytes, secret.Source, error) {
	if !s.specHasExplicit(spec) {
		return secret.New(nil), secret.SourceNone, nil
	}
	return s.acquire(spec)
}

// passphraseSpec builds the keystore-passphrase spec from the flag pair. A
// missing passphrase is the keystore auth class (keystore.passphrase_required,
// exit 4).
func passphraseSpec(stdin bool, file string, stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:    stdin,
		FilePath:     file,
		EnvVar:       envPassphrase,
		EnvFileVar:   envPassphraseFile,
		PromptLabel:  "Keystore passphrase: ",
		RequiredCode: "keystore.passphrase_required",
		StdinTaken:   stdinTaken,
	}
}

// confirmSpec builds the first-init confirmation spec from the confirm flag pair.
func confirmSpec(stdin bool, file string, stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:    stdin,
		FilePath:     file,
		EnvVar:       envPassphraseConfirm,
		EnvFileVar:   envPassphraseConfFile,
		PromptLabel:  "Confirm keystore passphrase: ",
		RequiredCode: "keystore.passphrase_required",
		StdinTaken:   stdinTaken,
	}
}

// adminSpec builds the ADMIN-passphrase spec (the policy mutation secret). A
// missing admin passphrase is the policy auth class
// (policy.admin_passphrase_required, exit 4), distinct from the keystore class.
func adminSpec(stdin bool, file string, stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:    stdin,
		FilePath:     file,
		EnvVar:       envAdminPassphrase,
		EnvFileVar:   envAdminPassphraseFile,
		PromptLabel:  "Admin passphrase: ",
		RequiredCode: "policy.admin_passphrase_required",
		StdinTaken:   stdinTaken,
	}
}

// adminNewSpec builds the NEW admin-passphrase spec for change-admin-passphrase.
func adminNewSpec(stdin bool, file string, stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:    stdin,
		FilePath:     file,
		EnvVar:       envAdminNewPassphrase,
		EnvFileVar:   envAdminNewPassFile,
		PromptLabel:  "New admin passphrase: ",
		RequiredCode: "policy.admin_passphrase_required",
		StdinTaken:   stdinTaken,
	}
}

// specHasExplicit reports whether any explicit source (flag, file, or env) is set
// for a spec — used to decide whether to acquire/prompt at all.
func (s *Service) specHasExplicit(spec secretSpec) bool {
	if spec.StdinFlag || spec.FilePath != "" {
		return true
	}
	lookup := s.secret.LookupEnv
	if lookup == nil {
		return false
	}
	if spec.EnvFileVar != "" {
		if v, ok := lookup(spec.EnvFileVar); ok && v != "" {
			return true
		}
	}
	if spec.EnvVar != "" {
		if _, ok := lookup(spec.EnvVar); ok {
			return true
		}
	}
	return false
}

// acquireConfirm resolves the first-init confirmation passphrase. With an explicit
// channel it resolves it; otherwise, at a TTY it prompts (double-entry); with no
// channel and no TTY it returns an empty secret so the keystore's first-init gate
// fails closed with keystore.confirm_required (never a hang).
func (s *Service) acquireConfirm(spec secretSpec) (*secret.Bytes, error) {
	if s.specHasExplicit(spec) {
		b, _, err := s.acquire(spec)
		return b, err
	}
	if s.secret.IsTTY != nil && s.secret.IsTTY() {
		b, _, err := s.acquire(spec)
		return b, err
	}
	return secret.New(nil), nil
}
