//go:build windows

package keys

import "github.com/daxchain-io/daxib/internal/fsx"

// chmodOwnerOnlyDir tightens a keystore directory's DACL to owner-only on Windows
// (§3.11). POSIX modes are not meaningful here; fsx.MkdirAll already applies an
// owner-only PROTECTED DACL when it CREATES a dir, but ensureDirs may be called on
// a PRE-EXISTING keystore dir (created out-of-band) whose DACL os.MkdirAll left
// untouched — so we re-apply the owner-only DACL here, mirroring the POSIX chmod
// 0700 on an existing dir. Best-effort: a tighten failure on a read-only mount
// surfaces as the dir being read-only via the caller's error mapping.
func chmodOwnerOnlyDir(path string) error { return fsx.SetOwnerOnlyDACL(path) }
