package policy

import (
	"crypto/rand"
	"time"
)

// crockford is the ULID Crockford-base32 alphabet (excludes I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulid returns a 26-char Crockford-base32 ULID: a 48-bit big-endian millisecond
// timestamp followed by 80 bits of entropy. Lexicographically sortable by creation
// time; stable and unique. ts comes from the engine's injected clock (reproducible
// in tests).
func ulid(ts time.Time) string {
	ms := uint64(ts.UnixMilli()) //nolint:gosec // G115: UnixMilli is non-negative for any real timestamp
	var buf [16]byte
	buf[0] = byte((ms >> 40) & 0xff)
	buf[1] = byte((ms >> 32) & 0xff)
	buf[2] = byte((ms >> 24) & 0xff)
	buf[3] = byte((ms >> 16) & 0xff)
	buf[4] = byte((ms >> 8) & 0xff)
	buf[5] = byte(ms & 0xff)
	if _, err := rand.Read(buf[6:]); err != nil {
		// crypto/rand failure is unrecoverable for id generation.
		panic("policy: cannot read entropy for ULID: " + err.Error())
	}
	return encodeCrockford(buf)
}

// encodeCrockford packs the 128-bit buffer into 26 base32 chars (130 bits; the top
// 2 bits are always zero).
func encodeCrockford(b [16]byte) string {
	out := make([]byte, 26)
	out[0] = crockford[(b[0]&0xff)>>5]
	out[1] = crockford[b[0]&0x1f]
	out[2] = crockford[(b[1]&0xff)>>3]
	out[3] = crockford[((b[1]<<2)|(b[2]>>6))&0x1f]
	out[4] = crockford[(b[2]>>1)&0x1f]
	out[5] = crockford[((b[2]<<4)|(b[3]>>4))&0x1f]
	out[6] = crockford[((b[3]<<1)|(b[4]>>7))&0x1f]
	out[7] = crockford[(b[4]>>2)&0x1f]
	out[8] = crockford[((b[4]<<3)|(b[5]>>5))&0x1f]
	out[9] = crockford[b[5]&0x1f]
	out[10] = crockford[(b[6]&0xff)>>3]
	out[11] = crockford[((b[6]<<2)|(b[7]>>6))&0x1f]
	out[12] = crockford[(b[7]>>1)&0x1f]
	out[13] = crockford[((b[7]<<4)|(b[8]>>4))&0x1f]
	out[14] = crockford[((b[8]<<1)|(b[9]>>7))&0x1f]
	out[15] = crockford[(b[9]>>2)&0x1f]
	out[16] = crockford[((b[9]<<3)|(b[10]>>5))&0x1f]
	out[17] = crockford[b[10]&0x1f]
	out[18] = crockford[(b[11]&0xff)>>3]
	out[19] = crockford[((b[11]<<2)|(b[12]>>6))&0x1f]
	out[20] = crockford[(b[12]>>1)&0x1f]
	out[21] = crockford[((b[12]<<4)|(b[13]>>4))&0x1f]
	out[22] = crockford[((b[13]<<1)|(b[14]>>7))&0x1f]
	out[23] = crockford[(b[14]>>2)&0x1f]
	out[24] = crockford[((b[14]<<3)|(b[15]>>5))&0x1f]
	out[25] = crockford[b[15]&0x1f]
	return string(out)
}
