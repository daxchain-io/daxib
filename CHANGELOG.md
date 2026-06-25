# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project scaffold (M1): compiling skeleton, `version` command (human +
  `--json`), architecture lattice (`internal/arch_test.go` enforcing one core,
  two frontends), and the CI/release pipeline (lint, race tests, cross-OS tests,
  six-target cross-compile, govulncheck, goreleaser snapshot, SHA-pinned actions).
