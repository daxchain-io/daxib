package keys

// scrypt cost parameters (§3.4). Standard is the production cost; light is a TEST
// escape hatch (DAXIB_KDF_LIGHT=1) that is honored ONLY when the manifest itself
// was created light — a flag in the manifest (Light) records that, so a
// production keystore can never be downgraded to light by setting an env var.
const (
	// stdScryptN is the production scrypt cost (2^18 = 262144).
	stdScryptN = 1 << 18
	// lightScryptN is the test-only scrypt cost (2^12 = 4096).
	lightScryptN = 1 << 12
)

// scryptN returns the scrypt N for this store. The store's light flag is set from
// the manifest at Open (or from DAXIB_KDF_LIGHT only on first init), so a
// production manifest (light=false) always uses stdScryptN even if the env var is
// set — preventing a silent downgrade.
func (s *Store) scryptN() int {
	if s.light {
		return lightScryptN
	}
	return stdScryptN
}
