package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxib/internal/policyseal"
)

// bodyVersion is the policy body schema version. A body with a higher version, or
// an unknown field, is a hard policy.version refusal (fail closed).
const bodyVersion = 1

// envelopeVersion / sealAlg are the outer-envelope constants.
const (
	envelopeVersion = 1
	sealAlg         = "scrypt/ed25519"
)

// nullSentinel is the in-memory marker for an explicit JSON `null` limit ("no limit
// on this network"), distinct from an absent field ("inherit the default"). The
// ordered writer renders it as a literal `null`; the strict decoder + tri-state
// reconciler set it when a field is present-but-null on the wire.
const nullSentinel = "\x00null\x00"

// Policy is the decoded Bitcoin policy body — the lean BTC schema (no
// tokens/typed-data/contracts, daxie's EVM machinery dropped). Amounts are
// decimal-string SATS. The struct field ORDER mirrors the canonical writer's key
// order; the seal covers the writer's bytes, not this struct's json marshaling.
type Policy struct {
	Version       int        `json:"version"`
	Nonce         uint64     `json:"nonce"`
	UpdatedAt     string     `json:"updated_at"`
	WrittenBy     string     `json:"written_by"`
	Rules         Rules      `json:"rules"`
	Allowlist     []PinEntry `json:"allowlist"`
	Denylist      []PinEntry `json:"denylist"`
	SelfAddresses []string   `json:"self_addresses"`
}

// Rules is the default limit block plus per-network overrides.
type Rules struct {
	Default  Limits        `json:"default"`
	Networks []NetworkRule `json:"networks"`
}

// Limits is the tri-state limit set. A nil *string is ABSENT (inherit the default
// block); a *string == nullSentinel is explicit NULL (no limit on this network); a
// *string value is the enforced decimal-sat amount. Bool limits are tri-state in
// the same way (nil = inherit, &false / &true = explicit). The default block always
// resolves every field (a nil there means "no limit").
type Limits struct {
	MaxTxSat    *string `json:"max_tx_sat"`
	MaxDaySat   *string `json:"max_day_sat"`
	MaxFeeRate  *string `json:"max_fee_rate_sat_vb"`
	AllowlistOn *bool   `json:"allowlist_enabled"`
	IncludeSelf *bool   `json:"include_self"`
}

// NetworkRule is a per-network limit override (the embedded Limits with the network
// key). Absent fields inherit the default block; null fields lift the limit.
type NetworkRule struct {
	Network string `json:"network"`
	Limits
}

// PinEntry is one allowlist/denylist row. v1 pins addresses only (source ==
// "address"); the source field is kept for forward-compat with contact/name pins.
type PinEntry struct {
	Source  string `json:"source"`
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
	AddedAt string `json:"added_at,omitempty"`
}

// envelope is the two-member on-disk wrapper: version + base64 body + the detached
// seal. Stored as a single file so a mutation is one atomic write and no torn
// body/seal pair is possible.
type envelope struct {
	Version int       `json:"version"`
	BodyB64 string    `json:"body_b64"`
	Seal    sealBlock `json:"seal"`
}

type sealBlock struct {
	Alg string `json:"alg"`
	Sig string `json:"sig"`
}

// ── the canonical body writer ─────────────────────────────────────────────────
//
// writeBody hand-builds the body bytes the seal covers, in a FIXED key order with
// decimal-string sat amounts and absent-vs-null tri-state. Two binaries at the same
// version produce byte-identical bodies (a reproducibility convenience, NOT a
// security property — the seal covers the STORED bytes, so a file written by any
// binary verifies under any other). The order is:
//
//	version, nonce, updated_at, written_by,
//	rules{default{...}, networks[{network, ...}]},
//	allowlist[], denylist[], self_addresses[]
func writeBody(p Policy) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	w := &fieldWriter{buf: &b}
	w.intField("version", p.Version)
	w.uintField("nonce", p.Nonce)
	w.strField("updated_at", p.UpdatedAt)
	w.strField("written_by", p.WrittenBy)
	w.rawKey("rules")
	writeRules(&b, p.Rules)
	w.afterRaw()
	w.rawKey("allowlist")
	writePins(&b, p.Allowlist)
	w.afterRaw()
	w.rawKey("denylist")
	writePins(&b, p.Denylist)
	w.afterRaw()
	w.rawKey("self_addresses")
	writeStrings(&b, sortedLower(p.SelfAddresses))
	w.afterRaw()
	b.WriteByte('}')
	return b.Bytes()
}

func writeRules(b *bytes.Buffer, r Rules) {
	b.WriteString(`{"default":`)
	writeLimits(b, r.Default, false)
	b.WriteString(`,"networks":[`)
	nets := append([]NetworkRule{}, r.Networks...)
	sort.Slice(nets, func(i, j int) bool { return nets[i].Network < nets[j].Network })
	for i, n := range nets {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"network":`)
		writeJSONString(b, n.Network)
		writeLimitsInline(b, n.Limits, true)
		b.WriteByte('}')
	}
	b.WriteString(`]}`)
}

// writeLimits writes the default block as a complete object (every field present in
// fixed order: a default-block nil limit is rendered as null = "no limit").
func writeLimits(b *bytes.Buffer, l Limits, perNetwork bool) {
	b.WriteByte('{')
	w := &fieldWriter{buf: b}
	writeLimitField(w, "max_tx_sat", l.MaxTxSat, perNetwork)
	writeLimitField(w, "max_day_sat", l.MaxDaySat, perNetwork)
	writeLimitField(w, "max_fee_rate_sat_vb", l.MaxFeeRate, perNetwork)
	writeBoolField(w, "allowlist_enabled", l.AllowlistOn, perNetwork)
	writeBoolField(w, "include_self", l.IncludeSelf, perNetwork)
	b.WriteByte('}')
}

// writeLimitsInline writes per-network override limits inline after the "network"
// key (so absent fields are simply omitted — inherit the default).
func writeLimitsInline(b *bytes.Buffer, l Limits, perNetwork bool) {
	w := &fieldWriter{buf: b, some: true} // some=true: a leading comma after "network"
	writeLimitField(w, "max_tx_sat", l.MaxTxSat, perNetwork)
	writeLimitField(w, "max_day_sat", l.MaxDaySat, perNetwork)
	writeLimitField(w, "max_fee_rate_sat_vb", l.MaxFeeRate, perNetwork)
	writeBoolField(w, "allowlist_enabled", l.AllowlistOn, perNetwork)
	writeBoolField(w, "include_self", l.IncludeSelf, perNetwork)
}

// writeLimitField renders one tri-state sat-limit field. perNetwork=true OMITS an
// absent field (inherit); perNetwork=false (the default block) renders an absent
// field as literal null (no limit). An explicit null renders as null either way.
func writeLimitField(w *fieldWriter, key string, p *string, perNetwork bool) {
	if p == nil {
		if perNetwork {
			return // inherit — omit
		}
		w.rawField(key, "null") // default block: nil = no limit
		return
	}
	if *p == nullSentinel {
		w.rawField(key, "null")
		return
	}
	w.rawField(key, jsonStringQuoted(*p))
}

func writeBoolField(w *fieldWriter, key string, p *bool, perNetwork bool) {
	if p == nil {
		if perNetwork {
			return
		}
		w.rawField(key, "false") // default block: nil bool defaults false
		return
	}
	if *p {
		w.rawField(key, "true")
	} else {
		w.rawField(key, "false")
	}
}

func writePins(b *bytes.Buffer, pins []PinEntry) {
	sorted := append([]PinEntry{}, pins...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source < sorted[j].Source
		}
		return sorted[i].Address < sorted[j].Address
	})
	b.WriteByte('[')
	for i, p := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"source":`)
		writeJSONString(b, p.Source)
		b.WriteString(`,"address":`)
		writeJSONString(b, p.Address)
		b.WriteString(`,"label":`)
		writeJSONString(b, p.Label)
		b.WriteString(`,"added_at":`)
		writeJSONString(b, p.AddedAt)
		b.WriteByte('}')
	}
	b.WriteByte(']')
}

func writeStrings(b *bytes.Buffer, ss []string) {
	b.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(b, s)
	}
	b.WriteByte(']')
}

// fieldWriter writes comma-separated "key":value pairs.
type fieldWriter struct {
	buf  *bytes.Buffer
	some bool
}

func (w *fieldWriter) comma() {
	if w.some {
		w.buf.WriteByte(',')
	}
	w.some = true
}
func (w *fieldWriter) strField(k, v string) {
	w.comma()
	writeJSONString(w.buf, k)
	w.buf.WriteByte(':')
	writeJSONString(w.buf, v)
}
func (w *fieldWriter) intField(k string, v int) {
	w.comma()
	writeJSONString(w.buf, k)
	w.buf.WriteByte(':')
	w.buf.WriteString(itoa(v))
}
func (w *fieldWriter) uintField(k string, v uint64) {
	w.comma()
	writeJSONString(w.buf, k)
	w.buf.WriteByte(':')
	w.buf.WriteString(utoa(v))
}
func (w *fieldWriter) rawField(k, raw string) {
	w.comma()
	writeJSONString(w.buf, k)
	w.buf.WriteByte(':')
	w.buf.WriteString(raw)
}

// rawKey writes "key": for a nested object/array the caller serializes itself; the
// caller MUST call afterRaw() after writing the value.
func (w *fieldWriter) rawKey(k string) {
	w.comma()
	writeJSONString(w.buf, k)
	w.buf.WriteByte(':')
}

// afterRaw is a no-op marker kept for symmetry/readability after a rawKey value.
func (w *fieldWriter) afterRaw() {}

// ── envelope marshal ──────────────────────────────────────────────────────────

// marshalEnvelope renders the two-member envelope in a fixed key order
// (version, body_b64, seal{alg, sig}).
func marshalEnvelope(bodyBytes, sig []byte) []byte {
	var b bytes.Buffer
	b.WriteString(`{"version":`)
	b.WriteString(itoa(envelopeVersion))
	b.WriteString(`,"body_b64":`)
	writeJSONString(&b, base64.StdEncoding.EncodeToString(bodyBytes))
	b.WriteString(`,"seal":{"alg":`)
	writeJSONString(&b, sealAlg)
	b.WriteString(`,"sig":`)
	writeJSONString(&b, base64.StdEncoding.EncodeToString(sig))
	b.WriteString(`}}`)
	return b.Bytes()
}

// ── decode + verify ───────────────────────────────────────────────────────────

// loadResult carries everything a loaded, verified policy needs: the decoded
// policy, the EXACT stored body bytes (the seal subject, re-signed verbatim on a
// mutation), and the envelope seal.
type loadResult struct {
	policy  Policy
	bodyRaw []byte
	seal    sealBlock
}

// decodeEnvelope parses the envelope and returns its body bytes + seal. A malformed
// envelope is a seal_violation (fail closed).
func decodeEnvelope(raw []byte) (envelope, []byte, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, nil, errSeal("unparseable", "policy.json envelope is malformed")
	}
	body, err := base64.StdEncoding.DecodeString(env.BodyB64)
	if err != nil {
		return envelope{}, nil, errSeal("unparseable", "policy.json body_b64 is not valid base64")
	}
	return env, body, nil
}

// verifyUnderAnchor verifies the seal over the EXACT body bytes against the
// anchor's pinned verify key (or the staged verify_key_next during rotation).
func verifyUnderAnchor(bodyRaw, sig []byte, anchor policyseal.Anchor) bool {
	if pk, err := anchor.VerifyKeyBytes(); err == nil && policyseal.Verify(bodyRaw, sig, pk) {
		return true
	}
	if pk, ok, err := anchor.VerifyKeyNextBytes(); err == nil && ok && policyseal.Verify(bodyRaw, sig, pk) {
		return true
	}
	return false
}

// decodeBodyStrict performs the second-pass strict decode (DisallowUnknownFields):
// an unknown field or a body version newer than this binary is a policy.version
// refusal (fail closed). It then reconciles the tri-state limits from the raw bytes
// so a present-null is preserved distinctly from absent.
func decodeBodyStrict(bodyRaw []byte) (Policy, error) {
	// Pass 1 (permissive): read version for the skew message.
	var head struct {
		Version   int    `json:"version"`
		WrittenBy string `json:"written_by"`
	}
	_ = json.Unmarshal(bodyRaw, &head)
	if head.Version > bodyVersion {
		return Policy{}, errVersion(head.WrittenBy, head.Version)
	}

	// Pass 2 (strict).
	dec := json.NewDecoder(bytes.NewReader(bodyRaw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, errVersion(head.WrittenBy, head.Version)
	}
	reconcileTriState(bodyRaw, &p)
	return p, nil
}

// reconcileTriState walks the raw body to distinguish present-null from absent for
// the per-network override limits (strict decode collapses both to a nil pointer).
// A present-null becomes the null sentinel so the writer re-emits literal null.
func reconcileTriState(bodyRaw []byte, p *Policy) {
	var probe struct {
		Rules struct {
			Default  json.RawMessage   `json:"default"`
			Networks []json.RawMessage `json:"networks"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(bodyRaw, &probe); err != nil {
		return
	}
	applyTriState(probe.Rules.Default, &p.Rules.Default)
	for i := range probe.Rules.Networks {
		if i < len(p.Rules.Networks) {
			applyTriState(probe.Rules.Networks[i], &p.Rules.Networks[i].Limits)
		}
	}
}

// applyTriState sets the null sentinel on any limit field that is present-and-null
// in raw.
func applyTriState(raw json.RawMessage, lim *Limits) {
	if len(raw) == 0 {
		return
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	setNullIfPresent(m, "max_tx_sat", &lim.MaxTxSat)
	setNullIfPresent(m, "max_day_sat", &lim.MaxDaySat)
	setNullIfPresent(m, "max_fee_rate_sat_vb", &lim.MaxFeeRate)
}

func setNullIfPresent(m map[string]json.RawMessage, key string, dst **string) {
	v, ok := m[key]
	if !ok {
		return
	}
	if string(bytes.TrimSpace(v)) == "null" {
		s := nullSentinel
		*dst = &s
	}
}

// ── shared json helpers ───────────────────────────────────────────────────────

func writeJSONString(b *bytes.Buffer, s string) {
	enc, _ := json.Marshal(s)
	b.Write(enc)
}

// base64Decode decodes a standard-encoding base64 string.
func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// NullSentinel returns the in-memory marker for an explicit-null ("lift the limit")
// tri-state value, for callers (the service input mapper) that build a Limits.
func NullSentinel() string { return nullSentinel }

// LimitString renders a tri-state limit pointer for display: nil/null → "" (no
// limit shown); a value → the decimal string.
func LimitString(p *string) string {
	if p == nil || *p == nullSentinel {
		return ""
	}
	return *p
}

func jsonStringQuoted(s string) string {
	enc, _ := json.Marshal(s)
	return string(enc)
}

func sortedLower(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, strings.ToLower(s))
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

func utoa(u uint64) string { return strconv.FormatUint(u, 10) }
