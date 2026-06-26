package service

import (
	"context"
	"sort"

	"github.com/daxchain-io/daxib/internal/domain"
)

// gapWindow is the forward look-ahead added to each branch's watermark when
// deriving the address set to scan (docs/PLAN.md §3.1 / §3.13: gap-limit-aware
// scanning). A balance therefore finds coins on addresses the wallet generated but
// has not yet "used" via `address new`. 20 is the BIP-44 standard gap limit.
const gapWindow = 20

// Balance derives the wallet's gap-window address set from the stored neutered
// xpub (NO passphrase, §3.5), dials the active backend, queries its UTXOs, and
// aggregates them into a confirmed / unconfirmed split (sats + exact BTC string).
// With req.UTXOs the individual coins are enumerated. The active --network must
// match the wallet's network.
func (s *Service) Balance(ctx context.Context, req domain.BalanceRequest) (domain.BalanceResult, error) {
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.BalanceResult{}, err
	}

	_, scan, err := s.keys.ScanAddresses(ctx, wallet, gapWindow)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	addrs := make([]string, len(scan))
	for i, a := range scan {
		addrs[i] = a.Address
	}

	client, backendName, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	defer client.Close()

	tip, err := client.TipHeight(ctx)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	utxos, err := client.UTXOs(ctx, addrs)
	if err != nil {
		return domain.BalanceResult{}, err
	}

	var confirmed, unconfirmed int64
	for _, u := range utxos {
		if u.Confirmations > 0 {
			confirmed += u.ValueSat
		} else {
			unconfirmed += u.ValueSat
		}
	}
	total := confirmed + unconfirmed

	out := domain.BalanceResult{
		Wallet:         wallet,
		Network:        s.net,
		Backend:        backendName,
		ConfirmedSat:   confirmed,
		UnconfirmedSat: unconfirmed,
		TotalSat:       total,
		ConfirmedBTC:   domain.SatsToBTC(confirmed),
		UnconfirmedBTC: domain.SatsToBTC(unconfirmed),
		TotalBTC:       domain.SatsToBTC(total),
		UTXOCount:      len(utxos),
		TipHeight:      tip,
	}
	if req.UTXOs {
		out.UTXOs = utxoRows(utxos)
	}
	return out, nil
}

// UTXOList derives the same gap-window set, queries the backend, and returns the
// per-UTXO breakdown (txid:vout, address, value, confirmations).
func (s *Service) UTXOList(ctx context.Context, req domain.UTXOListRequest) (domain.UTXOListResult, error) {
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.UTXOListResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.UTXOListResult{}, err
	}

	_, scan, err := s.keys.ScanAddresses(ctx, wallet, gapWindow)
	if err != nil {
		return domain.UTXOListResult{}, err
	}
	addrs := make([]string, len(scan))
	for i, a := range scan {
		addrs[i] = a.Address
	}

	client, backendName, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.UTXOListResult{}, err
	}
	defer client.Close()

	tip, err := client.TipHeight(ctx)
	if err != nil {
		return domain.UTXOListResult{}, err
	}
	utxos, err := client.UTXOs(ctx, addrs)
	if err != nil {
		return domain.UTXOListResult{}, err
	}

	var total int64
	for _, u := range utxos {
		total += u.ValueSat
	}
	return domain.UTXOListResult{
		Wallet:    wallet,
		Network:   s.net,
		Backend:   backendName,
		TipHeight: tip,
		UTXOs:     utxoRows(utxos),
		TotalSat:  total,
		TotalBTC:  domain.SatsToBTC(total),
	}, nil
}

// utxoRows projects domain.UTXOs to wire rows, sorted deterministically by
// (confirmations desc, outpoint) so a balance --utxos / utxo list output is
// stable across runs (a backend may return them in any order).
func utxoRows(utxos []domain.UTXO) []domain.UTXORow {
	rows := make([]domain.UTXORow, 0, len(utxos))
	for _, u := range utxos {
		rows = append(rows, domain.UTXORow{
			Outpoint:      u.Txid + ":" + domain.IndexString(u.Vout),
			Address:       u.Address,
			ValueSat:      u.ValueSat,
			ValueBTC:      domain.SatsToBTC(u.ValueSat),
			Confirmations: u.Confirmations,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Confirmations != rows[j].Confirmations {
			return rows[i].Confirmations > rows[j].Confirmations
		}
		return rows[i].Outpoint < rows[j].Outpoint
	})
	return rows
}
