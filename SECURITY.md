# Security Policy

Daxib handles wallet material, transaction signing, Bitcoin backend traffic, and
release artifacts. Please treat security reports with care and do not publish
exploit details, private keys, seed phrases, descriptors, backend credentials,
live wallet addresses with sensitive balances, or reproducible attacks against
third-party systems in a public issue.

## Supported Versions

Security fixes are planned for the current stable `v1.x` release line. Older
pre-release builds and release candidates are not supported unless a maintainer
explicitly asks you to reproduce against them.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting for this repository from the
repository's Security tab.

If that private reporting path is unavailable, open a minimal public issue
requesting a private security contact path. Do not include exploit details,
secrets, wallet material, or proof-of-concept code in the public issue.

Useful reports include:

- The Daxib version or commit tested.
- The operating system and architecture.
- Whether the issue affects CLI use, MCP server use, release artifacts,
  install scripts, Homebrew packaging, GHCR images, key storage, signing,
  policy enforcement, backend handling, or transaction broadcast.
- A minimal reproduction using testnet/signet/regtest or throwaway wallets only.
- The expected impact and any mitigations you have already tested.

## Scope

Security-sensitive areas include:

- Private-key, mnemonic, passphrase, descriptor, or keystore disclosure.
- Signing or broadcasting a transaction without the expected user or policy
  approval.
- Policy bypasses, spend-limit bypasses, fee-cap bypasses, name pin-drift
  bypasses, or incorrect destination/coin-selection handling.
- Unsafe defaults in backend, transaction, PSBT, fee, or receive flows.
- Release integrity problems, including checksum, Sigstore, SLSA provenance,
  Homebrew, install script, or GHCR image issues.
- MCP server behavior that could expose wallet state or trigger unexpected
  signing behavior.

Out of scope:

- Reports requiring compromised local administrator/root access without a
  Daxib-specific privilege boundary.
- Attacks against third-party Bitcoin backends, wallets, chains, package
  managers, or GitHub itself unless Daxib materially worsens the impact.
- Denial-of-service reports that do not affect wallet safety, release integrity,
  or local secret handling.

## Safe Testing

Use signet, testnet, regtest, throwaway wallets, and small balances. Daxib signs
and broadcasts Bitcoin transactions; mainnet transactions may be irreversible and
may result in loss of funds.

## Disclosure

Please allow a maintainer reasonable time to investigate and release a fix before
public disclosure. Daxib is maintained as public source for transparency, but
security coordination should still happen privately until users have a safe path
to update.
