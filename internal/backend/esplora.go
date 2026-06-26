package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

// esploraClient is the Esplora REST adapter (mempool.space-style paths). It is a
// thin, real set of GET/POST calls — never stubs that lie. The base URL is
// Options.URL with any trailing slash trimmed; the documented path scheme is:
//
//	GET  /blocks/tip/height        -> tip height (plain text integer)
//	GET  /address/:addr/utxo       -> [{txid,vout,value,status{confirmed,block_height}}]
//	GET  /fee-estimates            -> {"<target>": <sat/vB float>, ...}
//	POST /tx                       -> txid (plain text), body = raw hex
//	GET  /tx/:txid                 -> {status:{confirmed,block_height}}
//
// You trust the server's view (the §5 backend-trust residual); Bitcoin Core is the
// trust-minimized alternative.
type esploraClient struct {
	o    Options
	hc   *http.Client
	base string // URL with trailing slash trimmed
}

var _ Client = (*esploraClient)(nil)

func newEsploraClient(o Options, hc *http.Client) *esploraClient {
	return &esploraClient{o: o, hc: hc, base: strings.TrimRight(o.URL, "/")}
}

func (c *esploraClient) Close() {}

// TipHeight fetches GET /blocks/tip/height (a plain-text integer).
func (c *esploraClient) TipHeight(ctx context.Context) (int64, error) {
	body, err := c.get(ctx, "/blocks/tip/height", "tipheight")
	if err != nil {
		return 0, err
	}
	h, perr := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if perr != nil {
		return 0, rpcErr(c.o, "tipheight", "tip height is not an integer: "+truncate(string(body)))
	}
	return h, nil
}

// esploraUTXO is one element of GET /address/:addr/utxo.
type esploraUTXO struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"` // satoshis
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height"`
	} `json:"status"`
}

// UTXOs queries GET /address/:addr/utxo for every address and maps each output to
// a domain.UTXO, computing Confirmations from the current tip. One tip fetch
// serves all addresses (confirmations are tip-relative).
func (c *esploraClient) UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error) {
	tip, err := c.TipHeight(ctx)
	if err != nil {
		return nil, err
	}
	var out []domain.UTXO
	for _, addr := range addrs {
		body, gerr := c.get(ctx, "/address/"+addr+"/utxo", "utxos")
		if gerr != nil {
			return nil, gerr
		}
		var rows []esploraUTXO
		if jerr := json.Unmarshal(body, &rows); jerr != nil {
			return nil, rpcErr(c.o, "utxos", "malformed utxo JSON for "+addr+": "+jerr.Error())
		}
		for _, r := range rows {
			u := domain.UTXO{
				Txid:     r.Txid,
				Vout:     r.Vout,
				Address:  addr,
				ValueSat: r.Value,
			}
			if r.Status.Confirmed && r.Status.BlockHeight > 0 {
				u.Height = r.Status.BlockHeight
				u.Confirmations = confirmations(tip, r.Status.BlockHeight)
			}
			out = append(out, u)
		}
	}
	return out, nil
}

// FeeEstimates fetches GET /fee-estimates ({"<target>": <sat/vB>}). The float
// sat/vB values are rounded UP to the next integer (a conservative, never-underpay
// rounding) so the domain table stays float-free.
func (c *esploraClient) FeeEstimates(ctx context.Context) (domain.FeeEstimates, error) {
	body, err := c.get(ctx, "/fee-estimates", "feeestimates")
	if err != nil {
		return domain.FeeEstimates{}, err
	}
	var raw map[string]float64
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return domain.FeeEstimates{}, rpcErr(c.o, "feeestimates", "malformed fee-estimates JSON: "+jerr.Error())
	}
	est := domain.FeeEstimates{ByTarget: map[int]int64{}}
	for k, v := range raw {
		target, perr := strconv.Atoi(k)
		if perr != nil {
			continue
		}
		est.ByTarget[target] = ceilFee(v)
	}
	est.Fast = feeForTarget(est.ByTarget, 1)
	est.Normal = feeForTarget(est.ByTarget, 3)
	est.Slow = feeForTarget(est.ByTarget, 6)
	return est, nil
}

// Broadcast POSTs the raw tx hex to /tx and returns the echoed txid.
func (c *esploraClient) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	hexBody := hexEncode(rawTx)
	body, err := c.post(ctx, "/tx", "text/plain", []byte(hexBody), "broadcast")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// TxStatus fetches GET /tx/:txid and maps status.confirmed/block_height to a
// domain.TxStatus, computing Confirmations from the tip.
func (c *esploraClient) TxStatus(ctx context.Context, txid string) (domain.TxStatus, error) {
	body, err := c.get(ctx, "/tx/"+txid, "txstatus")
	if err != nil {
		return domain.TxStatus{}, err
	}
	var tx struct {
		Status struct {
			Confirmed   bool  `json:"confirmed"`
			BlockHeight int64 `json:"block_height"`
		} `json:"status"`
	}
	if jerr := json.Unmarshal(body, &tx); jerr != nil {
		return domain.TxStatus{}, rpcErr(c.o, "txstatus", "malformed tx JSON: "+jerr.Error())
	}
	out := domain.TxStatus{Txid: txid, Confirmed: tx.Status.Confirmed}
	if tx.Status.Confirmed && tx.Status.BlockHeight > 0 {
		tip, terr := c.TipHeight(ctx)
		if terr != nil {
			return domain.TxStatus{}, terr
		}
		out.BlockHeight = tx.Status.BlockHeight
		out.Confirmations = confirmations(tip, tx.Status.BlockHeight)
	}
	return out, nil
}

// get performs an HTTP GET against base+path, mapping transport failures to
// backend.unreachable and a non-2xx status to backend.rpc_error.
func (c *esploraClient) get(ctx context.Context, path, op string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, unreachableErr(c.o, op, err)
	}
	return c.do(req, op)
}

// post performs an HTTP POST with the given content type and body.
func (c *esploraClient) post(ctx context.Context, path, contentType string, body []byte, op string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, unreachableErr(c.o, op, err)
	}
	req.Header.Set("Content-Type", contentType)
	return c.do(req, op)
}

// do sends the request and reads the body, classifying errors.
func (c *esploraClient) do(req *http.Request, op string) ([]byte, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, unreachableErr(c.o, op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if rerr != nil {
		return nil, unreachableErr(c.o, op, rerr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, rpcErr(c.o, op, "HTTP "+strconv.Itoa(resp.StatusCode)+": "+truncate(string(body)))
	}
	return body, nil
}

// maxRespBytes caps a single backend response body (a defensive limit against a
// hostile/buggy server; the largest legitimate response here is a UTXO list).
const maxRespBytes = 8 << 20 // 8 MiB

// confirmations returns tip - height + 1 for a confirmed block, never negative.
func confirmations(tip, height int64) int64 {
	if height <= 0 || tip < height {
		return 0
	}
	return tip - height + 1
}

// feeForTarget returns the fee for the requested confirmation target, falling
// back to the nearest available target (the smallest target >= want, else the
// largest available) so a sparse table still yields a slow/normal/fast triple.
func feeForTarget(byTarget map[int]int64, want int) int64 {
	if v, ok := byTarget[want]; ok {
		return v
	}
	best, bestKey := int64(0), -1
	for k, v := range byTarget {
		if bestKey == -1 || abs(k-want) < abs(bestKey-want) {
			best, bestKey = v, k
		}
	}
	return best
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ceilFee rounds a sat/vB float UP to the next integer (never underpay).
func ceilFee(v float64) int64 {
	i := int64(v)
	if float64(i) < v {
		i++
	}
	if i < 1 {
		i = 1
	}
	return i
}

// truncate bounds an error fragment so a huge body cannot bloat a message.
func truncate(s string) string {
	const max = 200
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
