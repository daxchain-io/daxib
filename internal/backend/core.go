package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// coreClient is the Bitcoin Core JSON-RPC adapter. It is STATELESS — it never
// creates or loads a bitcoind wallet — so UTXOs are read with scantxoutset over
// address descriptors at the current tip (docs/ARCHITECTURE.md §6). Each method is a thin,
// real JSON-RPC call:
//
//	getblockcount                          -> TipHeight
//	scantxoutset start [addr(<a>), ...]    -> UTXOs (confirmed, at the tip)
//	estimatesmartfee <target>              -> FeeEstimates
//	sendrawtransaction <hex>               -> Broadcast
//	getrawtransaction <txid> true          -> TxStatus
//
// Auth is rpcuser/rpcpassword OR a bitcoind .cookie file (read fresh per request,
// since bitcoind rotates it on restart). The credentials are resolved by service
// before dialing; the cookie path is read here.
type coreClient struct {
	o  Options
	hc *http.Client
}

var _ Client = (*coreClient)(nil)

func newCoreClient(o Options, hc *http.Client) *coreClient {
	return &coreClient{o: o, hc: hc}
}

func (c *coreClient) Close() {}

// jsonRPCReq is the JSON-RPC 1.0 request shape bitcoind speaks.
type jsonRPCReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// jsonRPCResp is the response envelope. Result is decoded by the caller into the
// method-specific shape; Error is the bitcoind error object.
type jsonRPCResp struct {
	Result json.RawMessage `json:"result"`
	Error  *jsonRPCError   `json:"error"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// TipHeight calls getblockcount.
func (c *coreClient) TipHeight(ctx context.Context) (int64, error) {
	var h int64
	if err := c.call(ctx, "getblockcount", nil, &h, "tipheight"); err != nil {
		return 0, err
	}
	return h, nil
}

// scanResult is the scantxoutset response shape (the subset we consume). Amount
// is decoded as json.Number so the BTC->sat conversion is exact (no float drift).
type scanResult struct {
	Success  bool  `json:"success"`
	Height   int64 `json:"height"` // tip height the scan ran at
	Unspents []struct {
		Txid   string      `json:"txid"`
		Vout   uint32      `json:"vout"`
		Amount json.Number `json:"amount"` // BTC, exact decimal string
		Height int64       `json:"height"` // confirming block height
		Desc   string      `json:"desc"`
	} `json:"unspents"`
}

// UTXOs runs ONE scantxoutset over an addr(<a>) descriptor per address.
// scantxoutset returns CONFIRMED utxos at the current tip, with each output's
// confirming Height; Confirmations is computed from the scan's reported tip
// height. The BTC amount is converted to integer satoshis exactly (no float
// drift) via a decimal-string round-trip.
func (c *coreClient) UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	descs := make([]any, 0, len(addrs))
	for _, a := range addrs {
		descs = append(descs, "addr("+a+")")
	}
	var res scanResult
	if err := c.call(ctx, "scantxoutset", []any{"start", descs}, &res, "utxos"); err != nil {
		return nil, err
	}
	if !res.Success {
		return nil, rpcErr(c.o, "utxos", "scantxoutset reported success=false")
	}
	out := make([]domain.UTXO, 0, len(res.Unspents))
	for _, u := range res.Unspents {
		sat, serr := decimalBTCToSats(u.Amount.String())
		if serr != nil {
			return nil, rpcErr(c.o, "utxos", "non-integer-satoshi amount in scantxoutset result")
		}
		out = append(out, domain.UTXO{
			Txid:          u.Txid,
			Vout:          u.Vout,
			Address:       addrFromDesc(u.Desc),
			ValueSat:      sat,
			Height:        u.Height,
			Confirmations: confirmations(res.Height, u.Height),
		})
	}
	return out, nil
}

// FeeEstimates calls estimatesmartfee at the 1/3/6-block targets and folds the
// BTC/kvB rates into integer sat/vB (rounded up; never underpay).
func (c *coreClient) FeeEstimates(ctx context.Context) (domain.FeeEstimates, error) {
	est := domain.FeeEstimates{ByTarget: map[int]int64{}}
	for _, target := range []int{1, 3, 6} {
		var r struct {
			FeeRate float64  `json:"feerate"` // BTC per kvByte
			Errors  []string `json:"errors"`
		}
		if err := c.call(ctx, "estimatesmartfee", []any{target}, &r, "feeestimates"); err != nil {
			return domain.FeeEstimates{}, err
		}
		if r.FeeRate <= 0 {
			continue // no estimate available for this target
		}
		// BTC/kvB -> sat/vB: feerate * 1e8 / 1000 = feerate * 1e5.
		est.ByTarget[target] = ceilFee(r.FeeRate * 100_000)
	}
	est.Fast = feeForTarget(est.ByTarget, 1)
	est.Normal = feeForTarget(est.ByTarget, 3)
	est.Slow = feeForTarget(est.ByTarget, 6)
	return est, nil
}

// Broadcast calls sendrawtransaction and returns the txid.
func (c *coreClient) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	var txid string
	if err := c.call(ctx, "sendrawtransaction", []any{hex.EncodeToString(rawTx)}, &txid, "broadcast"); err != nil {
		return "", err
	}
	return txid, nil
}

// TxStatus calls getrawtransaction <txid> true and maps confirmations.
func (c *coreClient) TxStatus(ctx context.Context, txid string) (domain.TxStatus, error) {
	var r struct {
		Confirmations int64  `json:"confirmations"`
		BlockHash     string `json:"blockhash"`
	}
	if err := c.call(ctx, "getrawtransaction", []any{txid, true}, &r, "txstatus"); err != nil {
		return domain.TxStatus{}, err
	}
	out := domain.TxStatus{Txid: txid}
	if r.Confirmations > 0 {
		out.Confirmed = true
		out.Confirmations = r.Confirmations
		// Derive the confirming height from the tip and confirmation depth.
		tip, terr := c.TipHeight(ctx)
		if terr == nil {
			out.BlockHeight = tip - r.Confirmations + 1
		}
	}
	return out, nil
}

// call performs one JSON-RPC POST, decoding result into out. A transport failure
// is backend.unreachable; a JSON-RPC error object or malformed body is
// backend.rpc_error.
func (c *coreClient) call(ctx context.Context, method string, params []any, out any, op string) error {
	reqBody, merr := json.Marshal(jsonRPCReq{JSONRPC: "1.0", ID: "daxib", Method: method, Params: params})
	if merr != nil {
		return rpcErr(c.o, op, "encoding request: "+merr.Error())
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, c.o.URL, bytes.NewReader(reqBody))
	if rerr != nil {
		return unreachableErr(c.o, op, rerr)
	}
	req.Header.Set("Content-Type", "application/json")
	if aerr := c.authorize(req); aerr != nil {
		return aerr
	}

	resp, derr := c.hc.Do(req)
	if derr != nil {
		return unreachableErr(c.o, op, derr)
	}
	defer func() { _ = resp.Body.Close() }()
	body, berr := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if berr != nil {
		return unreachableErr(c.o, op, berr)
	}
	// bitcoind returns 401 on bad auth, 500 with a JSON-RPC error body on a method
	// error. Try to parse a JSON-RPC envelope first so the node's own message wins.
	var env jsonRPCResp
	if jerr := json.Unmarshal(body, &env); jerr != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return rpcErr(c.o, op, "HTTP "+strconv.Itoa(resp.StatusCode)+": "+truncate(string(body)))
		}
		return rpcErr(c.o, op, "malformed JSON-RPC response: "+jerr.Error())
	}
	if env.Error != nil {
		return rpcErr(c.o, op, "RPC error "+strconv.Itoa(env.Error.Code)+": "+env.Error.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return rpcErr(c.o, op, "HTTP "+strconv.Itoa(resp.StatusCode))
	}
	if out != nil {
		if jerr := json.Unmarshal(env.Result, out); jerr != nil {
			return rpcErr(c.o, op, "decoding "+method+" result: "+jerr.Error())
		}
	}
	return nil
}

// authorize sets HTTP Basic auth from rpcuser/rpcpassword or a fresh read of the
// .cookie file (bitcoind rotates the cookie on restart, so it is read per request,
// perms-checked like any secret file).
func (c *coreClient) authorize(req *http.Request) error {
	if c.o.CookieFile != "" {
		if perr := fsx.CheckPerms(c.o.CookieFile); perr != nil {
			return perr
		}
		data, err := os.ReadFile(c.o.CookieFile) // #nosec G304 -- operator-supplied cookie path, perms-checked above
		if err != nil {
			return unreachableErr(c.o, "auth", err)
		}
		user, pass, ok := strings.Cut(strings.TrimSpace(string(data)), ":")
		if !ok {
			return rpcErr(c.o, "auth", "cookie file is not in user:password form")
		}
		req.SetBasicAuth(user, pass)
		return nil
	}
	if c.o.RPCUser != "" || c.o.RPCPassword != "" {
		req.SetBasicAuth(c.o.RPCUser, c.o.RPCPassword)
	}
	return nil
}

// addrFromDesc extracts the address from a scantxoutset "addr(<a>)#checksum"
// descriptor so each UTXO can be attributed back to its address. Returns "" when
// the descriptor is not the addr() form.
func addrFromDesc(desc string) string {
	const prefix = "addr("
	i := strings.Index(desc, prefix)
	if i < 0 {
		return ""
	}
	rest := desc[i+len(prefix):]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
