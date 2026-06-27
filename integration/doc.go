// Package integration holds daxib's real-node (regtest bitcoind) end-to-end tests.
//
// The tests themselves live in files behind the `integration` build tag and run
// only via `go test -tags=integration ./integration/...`. This file carries no
// build tag so the package always has a buildable Go file (a normal `go build
// ./...` / `go test ./...` then sees an empty package rather than erroring on a
// directory whose every file is constrained out). See regtest_test.go.
package integration
