package service

import (
	"context"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/config"
	"github.com/daxchain-io/daxib/internal/domain"
)

// backend.go is the service-side backend composition root: it owns the config
// store mutators (add/list/use/remove), the Endpoint→backend.Options assembly
// (the one place ${env:}/${file:} secret references are resolved, transiently, at
// dial time — §7.5), the --backend > DAXIB_BACKEND > default-per-network selection
// precedence, and the `backend test` probe. service is the only package that
// legally imports BOTH config and backend (the arch matrix forbids that edge to
// either provider directly).

// requireConfig returns the config store or a clear backend.not_configured error
// when no --config / DAXIB_CONFIG path was supplied.
func (s *Service) requireConfig() (*config.Store, error) {
	if s.cfg == nil {
		return nil, domain.New(domain.CodeBackendNotConfigured,
			"no config file configured; set --config or DAXIB_CONFIG to manage backends")
	}
	return s.cfg, nil
}

// BackendAdd stores a named backend endpoint bound to a network. Secret values are
// stored RAW (as ${env:}/${file:} refs); a literal secret triggers a warning.
func (s *Service) BackendAdd(ctx context.Context, req domain.BackendAddRequest) (domain.BackendAddResult, []string, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.BackendAddResult{}, nil, err
	}
	network, err := s.backendNetwork(req.Network)
	if err != nil {
		return domain.BackendAddResult{}, nil, err
	}
	if _, perr := domain.ParseBackendType(string(req.Type)); perr != nil {
		return domain.BackendAddResult{}, nil, perr
	}

	ep := config.Endpoint{
		Network:    string(network),
		Type:       string(req.Type),
		URLRef:     req.URL,
		RPCUserRef: req.RPCUser,
		RPCPassRef: req.RPCPassword,
		CookieFile: req.RPCCookie,
	}
	warnings, err := store.AddEndpoint(ctx, req.Name, ep, false)
	if err != nil {
		return domain.BackendAddResult{}, nil, err
	}
	return domain.BackendAddResult{
		Name:    req.Name,
		Network: network,
		Type:    req.Type,
		URL:     config.MaskSecretRefs(req.URL),
	}, warnings, nil
}

// BackendList returns every configured backend (masked), optionally filtered to a
// network.
func (s *Service) BackendList(ctx context.Context, req domain.BackendListRequest) (domain.BackendListResult, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.BackendListResult{}, err
	}
	netFilter := ""
	if req.Network != "" {
		netFilter = string(req.Network)
	}
	views, err := store.ListEndpoints(netFilter)
	if err != nil {
		return domain.BackendListResult{}, err
	}
	out := domain.BackendListResult{Backends: make([]domain.BackendSummary, 0, len(views))}
	for _, v := range views {
		out.Backends = append(out.Backends, domain.BackendSummary{
			Name:    v.Name,
			Network: domain.Network(v.Network),
			Type:    domain.BackendType(v.Type),
			URL:     v.URL,
			Default: v.Default,
		})
	}
	return out, nil
}

// BackendUse makes a backend the default for ITS network.
func (s *Service) BackendUse(ctx context.Context, req domain.BackendUseRequest) (domain.BackendUseResult, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.BackendUseResult{}, err
	}
	network, err := store.UseEndpoint(ctx, req.Name)
	if err != nil {
		return domain.BackendUseResult{}, err
	}
	return domain.BackendUseResult{Name: req.Name, Network: domain.Network(network)}, nil
}

// BackendRemove removes a backend and clears any network default pointing at it.
func (s *Service) BackendRemove(ctx context.Context, req domain.BackendRemoveRequest) (domain.BackendRemoveResult, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.BackendRemoveResult{}, err
	}
	clearedFor, err := store.RemoveEndpoint(ctx, req.Name)
	if err != nil {
		return domain.BackendRemoveResult{}, err
	}
	return domain.BackendRemoveResult{Name: req.Name, ClearedFor: domain.Network(clearedFor)}, nil
}

// BackendTest dials the named backend (or the active network's default) and calls
// TipHeight, reporting the observed height + the round-trip latency. It proves the
// dial + auth + resolution path end-to-end. A dial failure surfaces as
// backend.unreachable (exit 6).
func (s *Service) BackendTest(ctx context.Context, req domain.BackendTestRequest) (domain.BackendTestResult, error) {
	name, ep, err := s.resolveBackend(req.Name)
	if err != nil {
		return domain.BackendTestResult{}, err
	}
	opts, err := s.backendOptions(ep)
	if err != nil {
		return domain.BackendTestResult{}, err
	}

	start := s.clock()
	client, err := s.dial(ctx, opts)
	if err != nil {
		return domain.BackendTestResult{}, err
	}
	defer client.Close()
	tip, err := client.TipHeight(ctx)
	if err != nil {
		return domain.BackendTestResult{}, err
	}
	latency := s.clock().Sub(start)

	return domain.BackendTestResult{
		Name:      name,
		Network:   domain.Network(ep.Network),
		Type:      domain.BackendType(ep.Type),
		URL:       config.MaskSecretRefs(ep.URLRef),
		TipHeight: tip,
		LatencyMS: latency.Milliseconds(),
	}, nil
}

// dialActiveBackend resolves and dials the backend for the active network (the
// balance/utxo path). It returns the dialed client, the resolved endpoint name,
// and the endpoint config (for the result's masked URL). The caller must Close.
func (s *Service) dialActiveBackend(ctx context.Context) (backend.Client, string, config.Endpoint, error) {
	// The implicit-backend path selects by the ACTIVE network; with no network
	// resolved there is nothing to select, so fail with usage.network_required rather
	// than a confusing backend.not_configured. (Explicit `backend test <name>` does
	// NOT go through here — it names its own endpoint and probes that network.)
	if err := s.requireNetwork(); err != nil {
		return nil, "", config.Endpoint{}, err
	}
	name, ep, err := s.resolveBackend("")
	if err != nil {
		return nil, "", config.Endpoint{}, err
	}
	opts, err := s.backendOptions(ep)
	if err != nil {
		return nil, "", config.Endpoint{}, err
	}
	client, err := s.dial(ctx, opts)
	if err != nil {
		return nil, "", config.Endpoint{}, err
	}
	return client, name, ep, nil
}

// resolveBackend applies the §6 selection precedence: an explicit name (the
// command's first arg) > the service's --backend/DAXIB_BACKEND override > the
// active network's default-backend. It returns the resolved name + endpoint, or a
// clear backend.not_configured/backend.not_found error.
func (s *Service) resolveBackend(explicit string) (string, config.Endpoint, error) {
	store, err := s.requireConfig()
	if err != nil {
		return "", config.Endpoint{}, err
	}

	name := explicit
	if name == "" {
		name = s.backend
	}
	if name == "" {
		def, derr := store.DefaultForNetwork(string(s.net))
		if derr != nil {
			return "", config.Endpoint{}, derr
		}
		if def == "" {
			return "", config.Endpoint{}, domain.Newf(domain.CodeBackendNotConfigured,
				"no backend configured for network %q; add one with `daxib backend add` and select it with `daxib backend use`", s.net)
		}
		name = def
	}

	ep, err := store.GetEndpoint(name)
	if err != nil {
		return "", config.Endpoint{}, err
	}
	// Guard the network match for the IMPLICIT selection paths only — the
	// active-network default or the --backend/DAXIB_BACKEND override — so a backend
	// bound to a different network than the active one is never used silently (the
	// same posture as the wallet network guard in account.go). An EXPLICIT
	// `backend test <name>` names a specific endpoint and is probed on its OWN
	// network (mirroring daxie's `rpc test <name>`), so it skips this guard.
	if explicit == "" && ep.Network != string(s.net) {
		return "", config.Endpoint{}, domain.Newf(domain.CodeUsage+".network_mismatch",
			"backend %q is bound to network %q but the active network is %q; pass --network %s or select a %s backend",
			name, ep.Network, s.net, ep.Network, s.net)
	}
	return name, ep, nil
}

// backendOptions assembles the fully-resolved backend.Options from a stored
// Endpoint, resolving its ${env:}/${file:} secret references HERE (transiently —
// the resolved values live only inside the returned Options and are never
// persisted, §7.5). The masked DisplayURL is supplied so error messages never
// leak a resolved credential.
func (s *Service) backendOptions(ep config.Endpoint) (backend.Options, error) {
	lookupEnv := s.secret.LookupEnv

	url, err := config.ResolveSecretRefs(ep.URLRef, lookupEnv)
	if err != nil {
		return backend.Options{}, err
	}
	user, err := config.ResolveSecretRefs(ep.RPCUserRef, lookupEnv)
	if err != nil {
		return backend.Options{}, err
	}
	pass, err := config.ResolveSecretRefs(ep.RPCPassRef, lookupEnv)
	if err != nil {
		return backend.Options{}, err
	}

	return backend.Options{
		Type:        domain.BackendType(ep.Type),
		URL:         url,
		DisplayURL:  config.RedactURLForError(ep.URLRef),
		Network:     domain.Network(ep.Network),
		RPCUser:     user,
		RPCPassword: pass,
		CookieFile:  ep.CookieFile,
		Timeout:     30 * time.Second,
	}, nil
}

// backendNetwork resolves the network for a backend mutation: the request's
// network if set, else the active network.
func (s *Service) backendNetwork(reqNet domain.Network) (domain.Network, error) {
	if reqNet != "" {
		return reqNet, nil
	}
	return s.net, nil
}
