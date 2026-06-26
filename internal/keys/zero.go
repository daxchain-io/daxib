package keys

import "runtime"

// zeroBytes overwrites b with zeros and keeps it alive past the loop so the
// compiler cannot elide the wipe (§3.10). Safe on nil/empty.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
