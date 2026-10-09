package main

// platform_adapters.go holds the control-plane adapters that bridge the
// data-plane core interfaces (session.ProxyPersister, configclient.Applier,
// meshresolver sources) to the platform clients. It compiles in the DEFAULT
// build but is the platform-only half of the wiring seam — every type here imports an
// internal/platform/* package, so none of it links into the self-hosted binary.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/meshresolver"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/usage"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

// tunnelIDIndex maps tunnel-svc row ids to local proxy ids so the
// configclient applier can unregister a proxy when a remote control-plane
// delete arrives. Safe for concurrent use.
type tunnelIDIndex struct{ m sync.Map }

func (t *tunnelIDIndex) set(tunnelID int64, proxyID string) { t.m.Store(tunnelID, proxyID) }
func (t *tunnelIDIndex) del(tunnelID int64)                 { t.m.Delete(tunnelID) }
func (t *tunnelIDIndex) get(tunnelID int64) (string, bool) {
	v, ok := t.m.Load(tunnelID)
	if !ok {
		return "", false
	}
	pid, ok := v.(string)
	return pid, ok
}

// tunnelPersisterAdapter satisfies session.ProxyPersister by translating
// the session-domain Proxy + Session into tunnel-svc CreateTunnel /
// ReportStatus / DeleteTunnel calls. All calls are best-effort: on
// transport failure we log and let the edge keep serving locally.
type tunnelPersisterAdapter struct {
	tc        *tunnelstore.Client
	logger    *slog.Logger
	edgeLabel string
	index     *tunnelIDIndex // populated so configclient applier can find proxy_id by tunnel_id
	// ports is this edge's TCP/UDP allocator. Held here for exactly one job:
	// when a Claim is refused because the port is already bound, the pool is
	// what was wrong, and reserving the port is what stops it happening again
	// for the life of the process.
	ports portReserver
	// usage is the metering reporter, held for one job too: a closing proxy is
	// the last moment its byte counters are readable, and the reporter only
	// ever walks LIVE sessions. nil on a node that reports no usage (SettleProxy
	// tolerates it). Set after construction — the reporter is wired later.
	usage *usage.Reporter
}

// portReserver is the sliver of router.PortPool this adapter needs. An
// interface so the failure path can be tested without a real pool.
type portReserver interface{ Reserve(port uint32) }

// portInUseReason is the status_reason prefix stamped on a tunnel whose claim
// was refused because its remote port is bound to another row on this edge.
// The port number follows, e.g. "port_in_use:20000". Same shape as
// store.IdleDisableReason: a code the consoles translate, never a sentence —
// this column is read by three UIs in ten languages.
const portInUseReason = "port_in_use:"

func (a *tunnelPersisterAdapter) OnProxyOpened(sess *session.Session, p *session.Proxy) (int64, error) {
	orgID, wsID := tunnelstore.ParseTenant(sess.TenantID, sess.WorkspaceID)

	// NEW_PROXY carried claim_tunnel_id ⇒ the client is claiming
	// a console-pre-created row, not creating a fresh one. Try Claim first;
	// if it fails for a reason that's safe to retry as a fresh insert
	// (most commonly: the pending row got deleted between push and claim),
	// fall through to the normal Persist path so the proxy still works.
	if p.ClaimTunnelID != 0 {
		res, err := a.tc.Claim(context.Background(), tunnelstore.ClaimInput{
			TunnelID:      p.ClaimTunnelID,
			OrgID:         orgID,
			ClientID:      sess.DeviceID,
			EdgeNodeLabel: a.edgeLabel,
			Domain:        p.Domain,
			RemotePort:    int32(p.RemotePort),
		})
		if err == nil {
			a.tc.ReportStatus(context.Background(), res.TunnelID, "enabled", "")
			if a.index != nil {
				a.index.set(res.TunnelID, p.ID)
			}
			applyProxyPolicy(a.logger, a.tc, p, res.ConfigJSON)
			a.logger.Info("claimed pending tunnel",
				"id", res.TunnelID, "proxy_id", p.ID, "type", string(p.Type))
			return res.TunnelID, nil
		}
		// an admin-disabled tunnel must HARD-FAIL here. Falling
		// through to Persist would mint a brand-new enabled row for the
		// same domain (reviving the tunnel) and then orphan-delete the
		// disabled row below — completely defeating the admin disable.
		// Return the error so handleNewProxy rolls back the local proxy and
		// the daemon surfaces a clear refusal instead of silently forwarding.
		if errors.Is(err, tunnelstore.ErrTunnelDisabled) {
			a.logger.Warn("claim refused: tunnel disabled (user or admin) — not reviving",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "domain", p.Domain)
			return 0, err
		}
		// The org reviews the tunnels its members create and this one is still
		// queued. Hard-fail for the same reason as the disable above, plus one
		// of its own: the Persist fallback would create ANOTHER row, which is
		// another member create in the same org and would queue as well — one
		// new pending tunnel per reconnect. Tagged with the session sentinel so
		// the daemon gets a code that means "waiting", not "duplicate".
		if errors.Is(err, tunnelstore.ErrTunnelAwaitingApproval) {
			a.logger.Info("claim refused: tunnel awaiting approval — not creating a second row",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "domain", p.Domain)
			return 0, fmt.Errorf("%w: %v", session.ErrProxyAwaitingApproval, err)
		}
		// a genuine ownership conflict (FailedPrecondition) must ALSO
		// hard-fail here. Falling through to Persist would mint a brand-new row
		// for this tunnel and orphan-delete the conflicting one — the exact loop
		// that left bursts of identical deleted TCP rows when a port tunnel
		// bounced between same-region edges. tunnel-svc now re-homes
		// same-client/same-region claims in place (base_domain match), so
		// reaching this branch means a real conflict (cross-region, different
		// client, or a still-live previous owner) that must surface — not be
		// papered over with a duplicate.
		if errors.Is(err, tunnelstore.ErrClaimConflict) {
			a.logger.Warn("claim refused: tunnel owned by another edge / conflict — not minting duplicate",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "domain", p.Domain, "remote_port", p.RemotePort)
			return 0, err
		}
		// The port this edge picked is still bound to another live row. Same
		// hard-fail as the two above — falling through to Persist would adopt
		// the row that holds the port and then SOFT-DELETE the one the user
		// created, so the tunnel they just made vanishes and somebody else's
		// older row takes its place. That is the loop the ErrClaimConflict
		// comment above describes; this is the case it missed.
		//
		// Unlike those two, this one is ours to fix: the number came out of this
		// process's pool, so reserve it. The pool then never offers it again for
		// the life of the edge, and the next attempt — a reconnect, or the
		// client's next NEW_PROXY — gets a port that is actually free.
		if errors.Is(err, tunnelstore.ErrPortBound) {
			if a.ports != nil && p.RemotePort != 0 {
				a.ports.Reserve(p.RemotePort)
			}
			// Say it on the ROW, not only in this log. The list otherwise goes
			// on showing 待接入 — the state of a tunnel nothing has picked up
			// yet — about one a running client already tried and was refused,
			// and since nothing retries a refused claim it says that forever.
			// A code, like tunnel-svc's idle_auto_disabled, not a sentence:
			// the consoles localize it. The next successful claim reports
			// "enabled" and clears it.
			if p.ClaimTunnelID != 0 {
				a.tc.ReportStatus(context.Background(), p.ClaimTunnelID, "error",
					fmt.Sprintf("%s%d", portInUseReason, p.RemotePort))
			}
			a.logger.Warn("claim refused: this port is already bound on this edge — "+
				"reserving it and refusing the proxy rather than replacing the user's tunnel row. "+
				"A cold port pool is the usual cause; check for a port pool DB-seed failure at boot",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "remote_port", p.RemotePort,
				"edge_node_id", a.tc.EdgeNodeID(), "err", err)
			return 0, err
		}
		// log every relevant scoping field at WARN so operators
		// can tell from the log whether the failure was NotFound, an
		// Org/Client precondition, or a Unique-index collision.
		a.logger.Warn("claim failed, falling back to Persist — orphan source row will be cleaned up post-Persist",
			"claim_tunnel_id", p.ClaimTunnelID,
			"err", err,
			"proxy_id", p.ID,
			"org_id", orgID,
			"workspace_id", wsID,
			"device_id", sess.DeviceID,
			"edge_node_id", a.tc.EdgeNodeID(),
			"edge_node_label", a.edgeLabel,
			"type", string(p.Type),
			"name", p.Name,
			"domain", p.Domain,
			"remote_port", p.RemotePort,
		)
	}

	res, err := a.tc.Persist(context.Background(), tunnelstore.PersistInput{
		OrgID:       orgID,
		WorkspaceID: wsID,
		ClientID:    sess.DeviceID,
		Name:        p.Name,
		Type:        string(p.Type),
		LocalAddr:   p.LocalAddr,
		Domain:      p.Domain,
		RemotePort:  int32(p.RemotePort),
		// What the user typed (`--ip-allow …`). Untrusted; tunnel-svc keeps
		// only the addresses. Sending it is what makes those flags mean
		// anything on a managed edge — they used to stop here.
		ProposedSecurityJSON: p.ProposedSecurityJSON,
	})
	if err != nil {
		// with the (edge_node_id, remote_port) unique check
		// now firing on the Persist path (CreateTunnel respects req.
		// edge_node_id), AlreadyExists here means a real port collision
		// — likely a race where two NEW_PROXYs landed on the same
		// freshly-restarted edge before its port pool was DB-seeded, or
		// a misuse where the same port was requested twice. Return the
		// error so handleNewProxy rolls back the local proxy and
		// surfaces it in NEW_PROXY_RESP. Without this rollback the
		// proxy would serve traffic locally but have no DB row → SPA
		// ghost + quota miscount.
		a.logger.Warn("persist tunnel failed",
			"err", err, "proxy_id", p.ID, "type", string(p.Type),
			"remote_port", p.RemotePort, "edge_node_id", a.tc.EdgeNodeID())
		// Tag a governance refusal so the session layer can give the client a
		// code that means what happened. This side is the only one that may
		// import gRPC status codes — internal/session matches the sentinel with
		// errors.Is instead (see internal/session/persist_error.go).
		//
		// FailedPrecondition from CreateTunnel is the org security baseline: it
		// is the only thing that returns it on this path, and the shape of any
		// future one would be the same — "the control plane will not record a
		// proxy like this", which is what the code says.
		if status.Code(err) == codes.FailedPrecondition {
			return 0, fmt.Errorf("%w: %s", session.ErrProxyPolicyRequired, err)
		}
		return 0, err
	}
	// The create SUCCEEDED and the row is parked: the org reviews what its
	// members publish. Refuse the proxy here — this is the CLI's only gate,
	// because on this path there is no claim to refuse. The row is kept (that
	// is the point: an admin has something to review), so nothing is rolled
	// back at the control plane; only the local proxy is.
	//
	// No ReportStatus either: "enabled" on a tunnel nothing serves would show
	// the member a live-looking row in the console and tell the offline-alert
	// sweep a lie.
	if res.Approval == "pending" {
		a.logger.Info("proxy refused: the organization reviews member tunnels and this one is queued",
			"tunnel_id", res.TunnelID, "proxy_id", p.ID, "type", string(p.Type),
			"domain", p.Domain, "org_id", orgID)
		return 0, session.ErrProxyAwaitingApproval
	}
	if res.TunnelID != 0 {
		// Mark online via ReportStatus so the row gets last_seen_at
		// stamped right at registration time.
		a.tc.ReportStatus(context.Background(), res.TunnelID, "enabled", "")
		if a.index != nil {
			a.index.set(res.TunnelID, p.ID)
		}
	}
	// orphan cleanup: when we got here via fallback (Claim
	// failed → Persist created a new row), the original row at
	// ClaimTunnelID is stranded — soft-delete it. Safe because the
	// only path setting ClaimTunnelID is the daemon's autoClaimOne,
	// which fires only after a CONFIG_PUSH that's already filtered to
	// sess.DeviceID == row.client_id; we're cleaning up our own orphan.
	if p.ClaimTunnelID != 0 && res.TunnelID != 0 && res.TunnelID != p.ClaimTunnelID {
		a.logger.Warn("cleaning up orphan row left by failed Claim",
			"orphan_tunnel_id", p.ClaimTunnelID,
			"new_tunnel_id", res.TunnelID,
			"proxy_id", p.ID)
		a.tc.Delete(context.Background(), p.ClaimTunnelID)
	}
	applyProxyPolicy(a.logger, a.tc, p, res.ConfigJSON)
	a.logger.Debug("persisted tunnel", "id", res.TunnelID, "proxy_id", p.ID)
	return res.TunnelID, nil
}

// applyProxyPolicy parses the tunnel row's server-authoritative config_json
// into the proxy's enforced security policy (IP allowlist, …). The blob comes
// from tunnel-svc's response — never from the daemon — so a tampered client
// can't strip its own restrictions. Best-effort + fail-open: a malformed blob
// logs and leaves Policy nil (allow all) so a config glitch never blackholes a
// tunnel. See apps/calabi-edge/internal/policy.
//
// Platform-only: a standalone edge applies client-supplied policy directly in
// session/controlloop.go, not via this server-authoritative path.
func applyProxyPolicy(logger *slog.Logger, secrets oauthSecretFetcher, p *session.Proxy, configJSON string) {
	pol, err := policy.Parse(configJSON)
	if err != nil {
		logger.Warn("parse tunnel security policy failed; serving without policy",
			"proxy_id", p.ID, "domain", p.Domain, "err", err)
		return
	}
	resolveOAuthSecret(context.Background(), logger, secrets, p, pol)
	p.SetPolicy(pol)
	if pol.HasIPRules() {
		logger.Info("tunnel security policy applied",
			"proxy_id", p.ID, "domain", p.Domain,
			"ip_allow", len(pol.IPAllow), "ip_deny", len(pol.IPDeny))
	}
}

// oauthSecretFetcher is the control-plane call that hands this edge the login
// credential for one tunnel. Satisfied by tunnelstore.Client.
type oauthSecretFetcher interface {
	OAuthSecret(ctx context.Context, tunnelID int64) (string, error)
}

// resolveOAuthSecret completes a policy that references an ORG LOGIN POLICY.
//
// The secret is deliberately not in config_json — it lives once, in the control
// plane — so a policy that names one arrives incomplete and has to be finished
// here, on the edge that is actually serving the tunnel.
//
// FAILING HERE IS NOT NEUTRAL. A policy left unresolved has no OAuth gate at
// all: the tunnel serves every visitor, and it looks exactly like a tunnel that
// was never meant to have a login. So a failure is logged at ERROR and the
// proxy keeps whatever policy it already had rather than being handed the
// gateless one — an SSO tunnel that stops responding is a bad afternoon, an SSO
// tunnel that silently stops asking who you are is a breach.
func resolveOAuthSecret(ctx context.Context, logger *slog.Logger, secrets oauthSecretFetcher, p *session.Proxy, pol *policy.Policy) {
	if !pol.NeedsOAuthSecret() {
		return
	}
	// A hot-swap can reuse what the live policy already resolved; only a fresh
	// registration has to go and ask.
	if live := p.LoadPolicy(); live != nil && live.OAuthPolicyRef() == pol.OAuthPolicyRef() {
		if err := pol.ResolveOAuthSecret(live.OAuthSecret()); err == nil {
			return
		}
	}
	if secrets == nil || p.TunnelID == 0 {
		logger.Error("tunnel references an org login policy but this edge cannot fetch its secret; "+
			"serving WITHOUT the login",
			"proxy_id", p.ID, "tunnel_id", p.TunnelID, "policy", pol.OAuthPolicyRef())
		return
	}
	secret, err := secrets.OAuthSecret(ctx, p.TunnelID)
	if err != nil {
		logger.Error("fetching the org login secret failed; serving WITHOUT the login",
			"proxy_id", p.ID, "tunnel_id", p.TunnelID, "policy", pol.OAuthPolicyRef(), "err", err)
		return
	}
	if err := pol.ResolveOAuthSecret(secret); err != nil {
		logger.Error("the org login secret did not produce a usable config; serving WITHOUT the login",
			"proxy_id", p.ID, "tunnel_id", p.TunnelID, "policy", pol.OAuthPolicyRef(), "err", err)
		return
	}
	logger.Info("org login policy resolved",
		"proxy_id", p.ID, "tunnel_id", p.TunnelID, "policy", pol.OAuthPolicyRef())
}

func (a *tunnelPersisterAdapter) OnProxyClosed(sess *session.Session, p *session.Proxy, reason string) {
	// FIRST, and before the tunnel_id check below: this is the last moment the
	// proxy's byte counters can be read. The usage reporter only walks live
	// sessions, so whatever moved since its last tick — all of it, for a tunnel
	// that opened and closed inside one interval — is lost the instant this
	// returns. Unattributed bytes (tunnel_id 0) count too; they are what keeps
	// the org total whole.
	a.usage.SettleProxy(sess, p)
	if p.TunnelID == 0 {
		return
	}
	// We mark offline rather than delete: deleting on every session
	// drop would race against quick client reconnects.
	a.tc.ReportStatus(context.Background(), p.TunnelID, "offline", reason)
	if a.index != nil {
		a.index.del(p.TunnelID)
	}
}

// portPoolController is the routeApplier's sliver of router.PortPool: a
// route set REPLACEMENT must both free numbers the server says are gone
// (Unreserve, the delete path) and take numbers newly owned by this
// edge out of circulation (Reserve, the snapshot/upsert path), so the
// pool never drifts from the confirmed tunnel set.
type portPoolController interface {
	Reserve(port uint32)
	Unreserve(port uint32)
}

// routeApplier wires configclient.Applier into the local router.
//
// It is the edge's transactional half of the config-generation
// protocol: configclient acks a generation only AFTER every step here
// has succeeded. The previously CONFIRMED route set (keyed by tunnel
// id) is kept in memory; each apply is a reconcile from that set to
// the target set, in this order:
//
//  1. CONFIG_PUSH to every ONLINE owning client FIRST — it is the only
//     step that can fail (broken client control stream). A client being
//     offline is success: its catch-up FullSync on the next handshake
//     reconciles its UI.
//  2. Local, non-failing effects: port-pool reserve/unreserve, router
//     teardown for deletes, hot policy swap for changed config_json.
//
// When step 1 fails nothing local has moved; any partial local effect
// from step 2 is undone and the caller (configclient) nacks the
// generation and resyncs from the confirmed cursor, so router, port
// pool, policy and the client UIs can never disagree across
// generations.
//
// scope (unchanged):
//   - delete + local edge: unregister via registrar (cross-process
//     "calabi delete" → all edges drop the route) + free the port
//   - upsert + local edge: keep the route (it is live from the client
//     session), hot-apply policy, pull the route's port out of the pool
//   - remote/edge_node_id=0 routes: locating/UI only — never touch the
//     local router or port pool
type routeApplier struct {
	edgeNodeID int64
	registrar  session.ProxyRegistrar
	manager    *session.Manager
	index      *tunnelIDIndex
	logger     *slog.Logger
	// secrets fetches an org login policy's credential. nil on a standalone
	// edge, which has no control plane to ask — resolveOAuthSecret says so
	// loudly rather than serving the tunnel without its login.
	secrets oauthSecretFetcher
	// baseDomain is this edge's HTTPListener.BaseDomain, used to resolve a
	// console tunnel's requested subdomain PREFIX to <prefix>.<base> before
	// forwarding the CONFIG_PUSH to the daemon (Phase 2).
	baseDomain string
	// ports is this edge's TCP/UDP pool, driven to match the confirmed local
	// route set: Reserve on snapshot/upsert, Unreserve on delete.
	ports portPoolController

	// mu guards confirmed + streamReserved. Applier calls are serialized by
	// configclient, but the manager's sessions read live proxies concurrently.
	mu sync.Mutex
	// confirmed is the last fully-applied stream route set (all edges). It
	// is the compensation target and the diff baseline.
	confirmed map[int64]configclient.Route
	// streamReserved is the set of ports THIS applier currently holds
	// reserved in the pool, so a reconcile never releases a port it did not
	// take (e.g. one the boot DB-seed or the persister owns).
	streamReserved map[uint32]struct{}
}

func indexRoutes(routes []configclient.Route) map[int64]configclient.Route {
	out := make(map[int64]configclient.Route, len(routes))
	for _, r := range routes {
		out[int64(r.ID)] = r
	}
	return out
}

func cloneRoutes(in map[int64]configclient.Route) map[int64]configclient.Route {
	out := make(map[int64]configclient.Route, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// OnSnapshot replaces the view with the server's full route set. Used on
// first connection and whenever the server cannot resume from the
// cursor. All steps succeed together or local state is compensated back
// to the confirmed set and an error is returned.
func (a *routeApplier) OnSnapshot(routes []configclient.Route) error {
	a.mu.Lock()
	from := cloneRoutes(a.confirmed)
	a.mu.Unlock()
	target := indexRoutes(routes)
	a.logger.Debug("snapshot received", "routes", len(routes))
	if err := a.reconcile(from, target, true); err != nil {
		a.compensate(from)
		return err
	}
	a.mu.Lock()
	a.confirmed = target
	a.mu.Unlock()
	return nil
}

// OnLocalDelta applies one locally-owned generation. The delta is
// authoritative about its BEFORE image, so a delete for a route the
// edge never cached (cold in-memory state after a restart) is seeded
// into the baseline — otherwise its port would never be freed.
func (a *routeApplier) OnLocalDelta(d configclient.Delta) error {
	a.mu.Lock()
	from := cloneRoutes(a.confirmed)
	a.mu.Unlock()
	target := cloneRoutes(from)
	switch d.Kind {
	case "delete":
		if _, known := target[int64(d.Route.ID)]; !known {
			from[int64(d.Route.ID)] = d.Route
		}
		delete(target, int64(d.Route.ID))
	case "upsert":
		target[int64(d.Route.ID)] = d.Route
	default:
		// Unknown kind: do nothing rather than guessing; the generation
		// still advances so the stream cannot wedge on a forward-compat tag.
		a.logger.Warn("local delta with unknown kind; applying no local change",
			"kind", d.Kind, "tunnel_id", d.Route.ID)
	}
	if err := a.reconcile(from, target, false); err != nil {
		a.compensate(from)
		return err
	}
	a.mu.Lock()
	a.confirmed = target
	a.mu.Unlock()
	return nil
}

// OnRemoteDelta only NOTE a route owned elsewhere (visitor locating) and
// best-effortly refreshes the owning client UI. It can never fail a
// generation: remote routes touch no local router/port/policy state, and
// a failed UI push behaves exactly as it did before generations existed.
func (a *routeApplier) OnRemoteDelta(d configclient.Delta) {
	a.mu.Lock()
	if a.confirmed == nil {
		a.confirmed = map[int64]configclient.Route{}
	}
	if d.Kind == "delete" {
		delete(a.confirmed, int64(d.Route.ID))
	} else {
		a.confirmed[int64(d.Route.ID)] = d.Route
	}
	a.mu.Unlock()
	a.logger.Debug("remote delta noted",
		"kind", d.Kind, "edge", d.Route.EdgeNodeID,
		"tunnel_id", d.Route.ID, "domain", d.Route.Domain)
	// even a "remote" route may belong to a client currently
	// connected to THIS edge (unassigned edge_node_id=0 routes land here).
	a.forwardToClient(d)
}

// reconcile drives live state from the confirmed set `from` to `target`.
// fullReplace=true sends per-client FullSync frames; false sends
// per-route upsert/close delta frames. Client notification runs first so
// its failure leaves all local state untouched.
func (a *routeApplier) reconcile(from, target map[int64]configclient.Route, fullReplace bool) error {
	if err := a.notifyClients(from, target, fullReplace); err != nil {
		return err
	}
	a.applyPortsAndRoutes(from, target)
	return nil
}

// compensate restores local effects after a failed reconcile. Client
// frames already on the wire cannot be recalled; the resync the caller
// triggers re-pushes the authoritative view, and a client reconnecting
// gets the same from its post-handshake catch-up.
func (a *routeApplier) compensate(confirmed map[int64]configclient.Route) {
	a.mu.Lock()
	from := cloneRoutes(a.confirmed)
	a.mu.Unlock()
	if len(from) == 0 && len(confirmed) == 0 {
		return
	}
	// A best-effort restore of ports/routes/policy; never errors outward.
	if err := a.reconcile(confirmed, from, false); err != nil {
		a.logger.Warn("compensation push failed; resync will restore", "err", err)
	}
	a.mu.Lock()
	a.confirmed = from
	a.mu.Unlock()
}

// notifyClients performs the CONFIG_PUSH half of a generation.
func (a *routeApplier) notifyClients(from, target map[int64]configclient.Route, fullReplace bool) error {
	if a.manager == nil {
		return nil
	}
	if fullReplace {
		// Every client mentioned by either side needs the authoritative
		// list (a client whose routes all vanished must get an empty
		// FullSync so its UI prunes them).
		cids := map[int64]struct{}{}
		for _, r := range from {
			if r.ClientID > 0 {
				cids[r.ClientID] = struct{}{}
			}
		}
		for _, r := range target {
			if r.ClientID > 0 {
				cids[r.ClientID] = struct{}{}
			}
		}
		for cid := range cids {
			sess := a.findClientSession(cid)
			if sess == nil {
				continue // offline: catch-up FullSync on next handshake
			}
			routes := make([]configclient.Route, 0)
			for _, r := range target {
				if r.ClientID == cid {
					routes = append(routes, r)
				}
			}
			if err := sess.SendControl(protocolFrameConfigPush,
				buildFullConfigPush(routes, a.baseDomain)); err != nil {
				return fmt.Errorf("full-sync CONFIG_PUSH to client %d: %w", cid, err)
			}
			a.logger.Info("snapshot full-sync pushed to client",
				"client_id", cid, "session_id", sess.ID, "n", len(routes))
		}
		return nil
	}

	// Delta mode: close routes removed (or re-homed away), upsert routes
	// added or materially changed.
	for id, old := range from {
		rnew, keep := target[id]
		if keep && rnew.EdgeNodeID == old.EdgeNodeID {
			continue
		}
		if old.ClientID <= 0 {
			continue
		}
		if err := a.pushOne(configclient.Delta{Kind: "delete", Route: old}); err != nil {
			return err
		}
	}
	for id, r := range target {
		old, existed := from[id]
		if existed && !routePushChanged(old, r) {
			continue
		}
		if r.ClientID <= 0 {
			continue
		}
		if err := a.pushOne(configclient.Delta{Kind: "upsert", Route: r}); err != nil {
			return err
		}
	}
	return nil
}

// routePushChanged reports whether the client-visible fields of a route
// changed (config_json is server-enforced at the edge and not pushed).
func routePushChanged(old, cur configclient.Route) bool {
	return old.Name != cur.Name ||
		old.Type != cur.Type ||
		old.LocalAddr != cur.LocalAddr ||
		old.Domain != cur.Domain ||
		old.Subdomain != cur.Subdomain ||
		old.RemotePort != cur.RemotePort ||
		old.Status != cur.Status
}

// pushOne forwards a single upsert/delete to its owning ONLINE session.
// No matching session (client offline) is success, not failure.
func (a *routeApplier) pushOne(d configclient.Delta) error {
	if a.manager == nil || d.Route.ClientID <= 0 {
		return nil
	}
	sess := a.findClientSession(d.Route.ClientID)
	if sess == nil {
		return nil
	}
	push := buildConfigPushFromDelta(d, a.baseDomain)
	if push == nil {
		return nil
	}
	if err := sess.SendControl(protocolFrameConfigPush, push); err != nil {
		return fmt.Errorf("CONFIG_PUSH %s tunnel %d to client %d: %w",
			d.Kind, d.Route.ID, d.Route.ClientID, err)
	}
	a.logger.Info("delta forwarded to client",
		"client_id", d.Route.ClientID,
		"session_id", sess.ID,
		"kind", d.Kind, "tunnel_id", d.Route.ID)
	return nil
}

// applyPortsAndRoutes mutates the local, non-failing half of a
// generation: the port pool tracks the local tcp/udp set, the router
// drops deleted proxies, policies hot-swap on config_json edits.
func (a *routeApplier) applyPortsAndRoutes(from, target map[int64]configclient.Route) {
	a.applyPortSet(from, target)
	a.applyRouteDeletes(from, target)
	a.applyPolicyUpserts(from, target)
}

// localTCPPorts is the set of remote ports the route set says THIS edge
// owns for tcp/udp rows.
func localTCPPorts(rs map[int64]configclient.Route, self int64) map[uint32]struct{} {
	out := map[uint32]struct{}{}
	for _, r := range rs {
		if r.EdgeNodeID != self || r.RemotePort <= 0 {
			continue
		}
		if r.Type == "tcp" || r.Type == "udp" {
			out[uint32(r.RemotePort)] = struct{}{}
		}
	}
	return out
}

func (a *routeApplier) applyPortSet(from, target map[int64]configclient.Route) {
	if a.ports == nil {
		return
	}
	oldPorts := localTCPPorts(from, a.edgeNodeID)
	newPorts := localTCPPorts(target, a.edgeNodeID)
	a.mu.Lock()
	tracked := make(map[uint32]struct{}, len(a.streamReserved))
	for p := range a.streamReserved {
		tracked[p] = struct{}{}
	}
	a.mu.Unlock()

	// Gone from the target: free the number. The candidate set unions what
	// this applier tracks with what the baseline names — a delete delta for
	// a cold-cache row must still release the port its row held.
	for p := range tracked {
		if _, want := newPorts[p]; want {
			continue
		}
		a.ports.Unreserve(p)
		delete(tracked, p)
	}
	for p := range oldPorts {
		if _, want := newPorts[p]; want {
			continue
		}
		if _, had := tracked[p]; had {
			continue
		}
		// The row is gone; this is the ONLY event allowed to free the
		// number (a proxy merely closing leaves its row live).
		a.ports.Unreserve(p)
	}
	// Newly owned: take the number out of circulation.
	for p := range newPorts {
		if _, have := tracked[p]; have {
			continue
		}
		a.ports.Reserve(p)
		tracked[p] = struct{}{}
	}

	a.mu.Lock()
	a.streamReserved = tracked
	a.mu.Unlock()
}

func (a *routeApplier) applyRouteDeletes(from, target map[int64]configclient.Route) {
	if a.index == nil {
		return
	}
	for id, old := range from {
		if old.EdgeNodeID != a.edgeNodeID {
			continue
		}
		if rnew, keep := target[id]; keep && rnew.EdgeNodeID == a.edgeNodeID {
			continue
		}
		proxyID, ok := a.index.get(id)
		if !ok {
			// Either we never knew this tunnel (stale delta after restart)
			// or it was already unregistered.
			a.logger.Debug("local delete: proxy_id not found in index",
				"tunnel_id", id)
			continue
		}
		a.registrar.UnregisterByProxyID(proxyID)
		a.index.del(id)
		a.logger.Info("local delete applied",
			"tunnel_id", id, "proxy_id", proxyID, "domain", old.Domain)
	}
}

func (a *routeApplier) applyPolicyUpserts(from, target map[int64]configclient.Route) {
	for id, r := range target {
		if r.EdgeNodeID != a.edgeNodeID {
			continue
		}
		if old, existed := from[id]; existed && old.ConfigJSON == r.ConfigJSON && old.Status == r.Status {
			continue
		}
		a.applyPolicyRoute(r)
	}
}

// applyPolicyRoute hot-swaps a live proxy's security policy when its
// tunnel's config_json changes. No-op (and safe) when the tunnel isn't
// currently served by this edge — the proxy picks up the policy at its
// next registration. Fail-open by design: a malformed blob keeps the
// current policy (serving must never blackhole over a config glitch),
// and a blob whose OAuth secret cannot be resolved keeps the live gate.
func (a *routeApplier) applyPolicyRoute(r configclient.Route) {
	if a.manager == nil || a.index == nil {
		return
	}
	proxyID, ok := a.index.get(int64(r.ID))
	if !ok {
		return // not live here yet — registration will apply the policy
	}
	pol, err := policy.Parse(r.ConfigJSON)
	if err != nil {
		a.logger.Warn("hot policy update: parse config_json failed; keeping current",
			"tunnel_id", r.ID, "err", err)
		return
	}
	// Find the live session that owns this proxy (the tunnel's client), then
	// swap the policy atomically — listeners reading it never see a torn value.
	target := a.findClientSession(r.ClientID)
	if target == nil {
		return
	}
	p := target.Proxy(proxyID)
	if p == nil {
		return
	}
	// A delta never carries the login secret — config_json does not have one to
	// carry. Without this the hot-swap would replace a working SSO gate with a
	// gateless policy every time somebody edited an unrelated field, and nothing
	// would say so. resolveOAuthSecret reuses what the live policy holds.
	resolveOAuthSecret(context.Background(), a.logger, a.secrets, p, pol)
	if pol.NeedsOAuthSecret() {
		a.logger.Error("hot policy update would drop this tunnel's login; keeping the current policy",
			"tunnel_id", r.ID, "policy", pol.OAuthPolicyRef())
		return
	}
	p.SetPolicy(pol)
	// Cut any ESTABLISHED keep-alive connection the new policy now denies, so a
	// fresh denylist entry takes effect immediately instead of only on the next
	// new connection (a browser holds its connection open otherwise).
	cut := target.CloseProxyConnsDenied(proxyID, pol)
	a.logger.Info("hot policy update applied",
		"tunnel_id", r.ID, "proxy_id", proxyID,
		"has_ip_rules", pol.HasIPRules(), "conns_cut", cut)
}

// findClientSession returns the live session for a device id, or nil
// when the owning client is offline.
func (a *routeApplier) findClientSession(clientID int64) *session.Session {
	if a.manager == nil || clientID <= 0 {
		return nil
	}
	var target *session.Session
	a.manager.All(func(s *session.Session) bool {
		if s.DeviceID == clientID {
			target = s
			return false // stop iteration
		}
		return true
	})
	return target
}

// forwardToClient finds the live session whose DeviceID matches
// d.Route.ClientID and best-effortly sends a CONFIG_PUSH frame
// announcing the upsert/delete. Failures are logged, not propagated:
// this is the remote-route/UI path and must never fail a generation.
func (a *routeApplier) forwardToClient(d configclient.Delta) {
	if err := a.pushOne(d); err != nil {
		a.logger.Debug("forward to client failed",
			"client_id", d.Route.ClientID, "err", err)
	}
}

// runDenySweeper pumps state from the usage deny hook into the live
// session set. Runs every 2s — denial signals are NATS-driven so this
// is just a "did the deny set change, propagate to sessions" loop.
//
// Sessions whose tenantID parses to an org_id present in the hook get
// SetBlockReason(reason); on Allow the block is cleared.
func runDenySweeper(ctx context.Context, logger *slog.Logger, mgr *session.Manager, hook *usage.DenyHook) error {
	if hook == nil {
		<-ctx.Done()
		return nil
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			mgr.All(func(s *session.Session) bool {
				org, err := strconvAtoi64(s.TenantID)
				if err != nil || org <= 0 {
					return true
				}
				blocked, reason := hook.IsBlocked(org)
				if blocked {
					if was, _ := s.IsBlocked(); !was {
						logger.Info("session blocked by usage deny",
							"session_id", s.ID, "org", org, "reason", reason)
					}
					s.SetBlockReason(reason)
				} else {
					if was, _ := s.IsBlocked(); was {
						logger.Info("session unblocked",
							"session_id", s.ID, "org", org)
					}
					s.SetBlockReason("")
				}
				return true
			})
		}
	}
}

// usageReportInterval reads CALABI_USAGE_REPORT_INTERVAL_MS to override
// the usage reporter cadence.
// Unset / 0 / invalid keeps the
// usage.DefaultReportInterval (60s). The metering bucket is still
// per-minute, so 60s is the finest useful setting; 300s ≈ ÷5 cost.
func usageReportInterval(logger *slog.Logger) time.Duration {
	v := os.Getenv("CALABI_USAGE_REPORT_INTERVAL_MS")
	if v == "" {
		return 0
	}
	ms, err := strconvAtoi64(v)
	if err != nil || ms <= 0 {
		logger.Warn("ignoring invalid CALABI_USAGE_REPORT_INTERVAL_MS", "value", v)
		return 0
	}
	d := time.Duration(ms) * time.Millisecond
	logger.Info("usage report interval overridden", "interval", d.String())
	return d
}

// meshOwnerSource adapts *tunnelstore.Client to meshresolver.OwnerSource,
// mapping the tunnelstore.OwnerEntry wire shape to meshresolver.Owner.
// Works in both cluster mode and bff-edge mode (bff-edge proxies
// ResolveOwners + ListEdges as of 2026-06-03, so same-region mesh runs
// over the bff-edge gateway too).
type meshOwnerSource struct{ tc *tunnelstore.Client }

func (m meshOwnerSource) ResolveOwners(ctx context.Context, baseDomain, knownGen string) ([]meshresolver.Owner, string, bool, error) {
	rows, gen, unchanged, err := m.tc.ResolveOwners(ctx, baseDomain, knownGen)
	if err != nil {
		return nil, "", false, err
	}
	if unchanged {
		return nil, gen, true, nil
	}
	out := make([]meshresolver.Owner, 0, len(rows))
	for _, r := range rows {
		out = append(out, meshresolver.Owner{Domain: r.Domain, EdgeNodeID: r.EdgeNodeID})
	}
	return out, gen, false, nil
}

// meshEdgeDirectory adapts *identity.Verifier to meshresolver.EdgeDirectory.
type meshEdgeDirectory struct{ v *identity.Verifier }

func (m meshEdgeDirectory) ListEdges(ctx context.Context, region string) ([]meshresolver.Edge, error) {
	rows, err := m.v.ListEdges(ctx, region)
	if err != nil {
		return nil, err
	}
	out := make([]meshresolver.Edge, 0, len(rows))
	for _, e := range rows {
		out = append(out, meshresolver.Edge{
			EdgeNodeID:   e.EdgeNodeID,
			Region:       e.Region,
			InternalAddr: e.InternalAddr,
			Healthy:      e.Healthy,
		})
	}
	return out, nil
}
