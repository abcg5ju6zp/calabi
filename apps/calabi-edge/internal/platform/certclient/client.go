// Package certclient pulls TLS certificates from cert-svc into a chain
// of RECOVERABLE GENERATIONS, each backing tls.Config.GetCertificate for
// the edge HTTPS listener.
//
// THE FAILURE THIS PACKAGE EXISTED TO HAVE
// ----------------------------------------
// A catalog refresh used to rebuild the serving pool from ListCerts and
// swap it in even when some GetCert calls failed: a rotation window during
// which only part of the (new) private keys came down replaced the still
// healthy OLD pool with an INCOMPLETE one. When the event stream then
// dropped — or the process restarted — domains that were serving fine
// started failing TLS handshakes, and stayed failed until the missing key
// happened to arrive.
//
// GENERATIONS
// -----------
// Every change (push upsert/delete, or a full ListCerts reconcile) produces
// a candidate generation first:
//
//   - For a reconcile: ListCerts metas define the candidate; EVERY listed
//     cert must be fetched (GetCert) and parsed before the candidate is
//     committed. If any fetch/parse fails, the ACTIVE generation keeps
//     serving and only the missing cert ids are retried on their own
//     timer; the partial candidate is never published.
//   - For a push: the single cert is fetched/parsed and applied as a delta
//     to the active generation; a failed fetch changes nothing and kicks a
//     reconcile rather than evicting anything.
//
// Each committed generation is sealed and atomically PUBLISHED TO DISK (an
// encrypted snapshot under state.dir; see snapshot.go). On startup, if the
// control plane cannot be reached, the last confirmed snapshot is loaded
// and served. A failed snapshot publish leaves the previous snapshot file
// intact; the next tick re-publishes.
//
// ORDERING — OLD LISTS, DUPLICATE EVENTS, DELETES
// -----------------------------------------------
// Each entry carries the server watermark (the row's updated_at nanos); a
// listing/full-pull reconciliation never downgrades an entry with a newer
// watermark already serving. A push-installed entry NEWER than a NON-EMPTY
// listing's as-of watermark survives a stale listing that merely omits it;
// entries older than the listing as-of are evicted, so the listing stays
// authoritative for scope and deletion (including BYOI scope). An EMPTY
// successful listing has no as-of to compare, so it stays authoritative
// outright and evicts everything (the historical behaviour). Confirmed
// deletes leave a TOMBSTONE (id → version): a stale listing cannot
// resurrect a cert newer than the delete. Duplicate/redelivered events are
// no-ops (fingerprint dedup; delete-id-and-version dedup), which is also
// what makes "event applied, ack lost" safe to replay.
//
// AFTER AN EVENT-STREAM RECONNECT
// -------------------------------
// The bus fires RequestResync when a cert stream re-opens: the next poller
// turn ListCerts and compares the SERVER generation digest
// (id|fingerprint|version over the listing) with the active generation's
// projected digest. Equal means no event was missed; different means a
// full reconcile. Polling cadence is unchanged: 5 min with a bus (push
// primary, poll backstop), 30 s without one.
//
// PRESERVED BEHAVIOUR
// -------------------
// In-flight handshakes hold the *tls.Certificate pointer crypto/tls asked
// for at handshake start — swaps never touch them. Wildcard SNI matching,
// BYOI PermissionDenied on ListCerts (serve locally-provisioned certs),
// and the no-bus 30 s poll-only mode are unchanged.
package certclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabinet/calabi/pkg/certevents"
	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// DefaultRefreshInterval governs how often the client re-polls cert-svc
// when NATS is wired (push primary, poll as belt-and-suspenders).
const DefaultRefreshInterval = 5 * time.Minute

// LegacyPollInterval is the original cadence — used when no event bus
// is configured so the edge keeps full visibility via polling alone.
const LegacyPollInterval = 30 * time.Second

// missingRetryInterval bounds how long a failed GetCert keeps a complete
// new generation from going live: only the missing ids are retried.
const missingRetryInterval = 15 * time.Second

// rpcTimeout bounds every control-plane call made from this package.
const rpcTimeout = 10 * time.Second

// ErrNoCertForSNI is what GetCertificate returns when a TLS visitor's
// ClientHello.ServerName isn't in the active map. crypto/tls turns this
// into a TLS-level "no_cert" alert; the visitor sees a handshake failure.
var ErrNoCertForSNI = errors.New("certclient: no certificate for SNI")

// errIncompleteGeneration is returned by refresh when the listing came
// back but at least one listed cert could not be fetched or parsed. The
// active generation is still serving; pending ids are retried separately.
var errIncompleteGeneration = errors.New("certclient: candidate generation incomplete; keeping active generation")

// Options configures Start.
type Options struct {
	// Addr is the cert-svc gRPC endpoint, e.g. "127.0.0.1:7005". Kept for
	// option-shape compatibility; every edge reaches cert-svc through the
	// pre-dialed RPC handed to StartWithClient.
	Addr string
	// OrgID limits the fetch to one org. ZERO means this node is a PLATFORM
	// edge — it serves every org and wants every org's certs.
	//
	// Both halves of that are decided by bff-edge from the caller's mTLS cert,
	// not here: it overwrites org_id and sets all_orgs before the request
	// reaches cert-svc. So this value is what the node believes about itself
	// (config.Config.OrgID, itself read from the same certificate) and cannot
	// widen the node's own scope.
	OrgID int64
	// RefreshInterval overrides the default poll cadence. Zero picks
	// the right default for the wiring: 5 minutes when a Bus is set
	// (push primary, poll as backstop), 30 seconds when not (poll-only).
	RefreshInterval time.Duration
	// Bus, when non-nil, enables the cert-push path. The client
	// subscribes to calabi.cert.upsert.> and calabi.cert.delete.>
	// during Start() and applies events incrementally.
	Bus eventbus.Bus
	// StateDir is where the encrypted generation snapshot and its 0600
	// key live (cfg.State.Dir). Empty disables persistence: the node is
	// then exactly as recoverable as the control plane is at boot.
	StateDir string
}

// Client owns the cert-svc grpc connection + the polling goroutine + the
// atomic active generation of *tls.Certificate keyed by SNI host.
//
// Safe for concurrent reads (GetCertificate); generation commits happen
// only on the polling goroutine or an event-handler goroutine, and writeMu
// serialises them. RPC is the narrow subset of pb.CertClient edge uses.
// bff_edge.BFFEdgeClient satisfies it directly.
type RPC interface {
	GetCert(ctx context.Context, in *pb.GetCertRequest, opts ...grpc.CallOption) (*pb.GetCertResponse, error)
	ListCerts(ctx context.Context, in *pb.ListCertsRequest, opts ...grpc.CallOption) (*pb.ListCertsResponse, error)
}

type Client struct {
	rpc    RPC
	logger *slog.Logger
	orgID  int64

	// pool is the active generation. Never nil after construction; swapped
	// atomically; readers never take writeMu.
	pool atomic.Pointer[generation]

	// writeMu serialises generation commits across the polling goroutine
	// and the NATS event handlers, and guards seq / persistedSeq.
	writeMu      sync.Mutex
	seq          uint64
	persistedSeq uint64

	bus    eventbus.Bus
	upsert eventbus.Subscription
	delete eventbus.Subscription

	store *snapshotStore

	// pending is the not-yet-complete candidate of the LAST refresh whose
	// listing came back whole but whose GetCerts did not. Touched ONLY by
	// the polling goroutine (retryPending) and StartWithClient's initial
	// refresh, which runs before the poller starts.
	pending *pendingFetch

	// kick fires an out-of-band reconcile (stream reconnect; push fetch
	// failure). Buffer 1: a signal while one is already queued collapses.
	kick chan struct{}

	stopCh   chan struct{}
	stopOnce func()
}

// certEntry is one fetched certificate plus the server metadata that
// orders it relative to other copies of the same cert_id. The PEM pair is
// retained so the generation can be snapshotted without a refetch.
type certEntry struct {
	id          int64
	orgID       int64
	cert        *tls.Certificate
	sans        []string // normalized, non-empty
	subject     string   // normalized; "" when none
	fingerprint string
	version     int64 // server watermark: row updated_at unix nanos; 0 = unknown

	fullchainPEM  []byte
	privateKeyPEM []byte
}

// generation is one immutable serving view. bySNI is a pure projection of
// entries; fingerprints names the cert currently installed for a leaf
// hash; tombstones records cert ids confirmed deleted (value = delete
// version watermark).
type generation struct {
	seq        uint64
	digest     string // server-generation digest projected from entries
	entries    map[int64]*certEntry
	tombstones map[int64]int64

	bySNI             map[string]*tls.Certificate
	fingerprintOwners map[string]int64
}

// pendingFetch is a candidate waiting on individual GetCert retries.
type pendingFetch struct {
	metas   []*pb.CertMeta // listing order
	byID    map[int64]*pb.CertMeta
	digest  string
	asOf    int64
	got     map[int64]*certEntry
	missing map[int64]struct{}
}

// emptyGeneration returns a zero-entry generation with seq 0.
func emptyGeneration() *generation {
	return projectGeneration(0, nil, nil)
}

// projectGeneration builds the immutable view: it sorts cert ids so SAN
// conflicts resolve deterministically (higher server version wins; ties go
// to the larger id), projects bySNI, and computes the digest a ListCerts
// of exactly these certs (id|fingerprint|version) would carry.
func projectGeneration(seq uint64, entries map[int64]*certEntry, tombstones map[int64]int64) *generation {
	g := &generation{
		seq:               seq,
		entries:           entries,
		tombstones:        tombstones,
		bySNI:             map[string]*tls.Certificate{},
		fingerprintOwners: map[string]int64{},
	}
	// owner names the entry whose cert currently backs each SNI key, so a
	// later entry only replaces it when entryBeats says so.
	owner := map[string]int64{}
	for _, id := range sortedInt64Keys(entries) {
		e := entries[id]
		if e.fingerprint != "" {
			g.fingerprintOwners[e.fingerprint] = e.id
		}
		keys := make([]string, 0, len(e.sans)+1)
		keys = append(keys, e.sans...)
		if e.subject != "" && !containsString(keys, e.subject) {
			keys = append(keys, e.subject)
		}
		for _, key := range keys {
			if holderID, taken := owner[key]; taken {
				if !entryBeats(e, entries[holderID]) {
					continue
				}
			}
			owner[key] = id
			g.bySNI[key] = e.cert
		}
	}
	g.digest = digestEntries(entries)
	return g
}

// entryBeats reports whether candidate should win an SNI key from holder:
// strictly newer watermark, or equal watermark with a larger cert id.
func entryBeats(candidate, holder *certEntry) bool {
	if candidate.version != holder.version {
		return candidate.version > holder.version
	}
	return candidate.id > holder.id
}

// digestLines hashes ordered "id:fingerprint:version" lines. It is the
// server generation identity: the same listing projected later, the same
// pushes replayed, and a snapshot reloaded all produce the same digest.
func digestLines(lines []string) string {
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func digestEntries(entries map[int64]*certEntry) string {
	lines := make([]string, 0, len(entries))
	for _, id := range sortedInt64Keys(entries) {
		e := entries[id]
		lines = append(lines, fmt.Sprintf("%d:%s:%d", id, e.fingerprint, e.version))
	}
	return digestLines(lines)
}

// listingDigest computes the same identity straight from a ListCerts
// response, so refresh can compare listing vs active WITHOUT pulling a
// single private key.
func listingDigest(metas []*pb.CertMeta) string {
	ids := make([]int64, 0, len(metas))
	byID := make(map[int64]*pb.CertMeta, len(metas))
	for _, m := range metas {
		id := m.GetMeta().GetId()
		ids = append(ids, id)
		byID[id] = m
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	lines := make([]string, 0, len(ids))
	for _, id := range ids {
		m := byID[id]
		lines = append(lines, fmt.Sprintf("%d:%s:%d", id, m.GetFingerprint(), metaVersion(m)))
	}
	return digestLines(lines)
}

// listingAsOf is the max row watermark in the listing — the timestamp up
// to which the listing is authoritative. Pushed entries strictly newer
// than it cannot have been known to this listing.
func listingAsOf(metas []*pb.CertMeta) int64 {
	var asOf int64
	for _, m := range metas {
		if v := metaVersion(m); v > asOf {
			asOf = v
		}
	}
	return asOf
}

func metaVersion(m *pb.CertMeta) int64 {
	if ts := m.GetMeta().GetUpdatedAt(); ts != nil {
		return ts.AsTime().UnixNano()
	}
	return 0
}

// StartWithClient is the constructor for bff-edge mode: the caller passes
// a pre-made RPC (typically a shared bff_edge.BFFEdgeClient) and Bus
// (typically bffedgeclient.NewBus), and StartWithClient skips the
// cert-svc dial.
func StartWithClient(ctx context.Context, logger *slog.Logger, client RPC, opts Options) (*Client, error) {
	if client == nil {
		return nil, errors.New("certclient: nil RPC")
	}
	if opts.RefreshInterval <= 0 {
		if opts.Bus != nil {
			opts.RefreshInterval = DefaultRefreshInterval
		} else {
			opts.RefreshInterval = LegacyPollInterval
		}
	}
	c := &Client{
		rpc:    client,
		logger: logger.With("component", "certclient"),
		orgID:  opts.OrgID,
		bus:    opts.Bus,
		stopCh: make(chan struct{}),
		kick:   make(chan struct{}, 1),
	}
	if dir := strings.TrimSpace(opts.StateDir); dir != "" {
		c.store = newSnapshotStore(dir, c.logger)
	}
	c.pool.Store(emptyGeneration())

	// Recover the last CONFIRMED generation before any network call. A boot
	// during a control-plane outage then serves exactly what was confirmed,
	// instead of an empty pool; the first successful refresh supersedes it.
	var loaded *generation
	if c.store != nil {
		g, err := c.store.load()
		switch {
		case err != nil:
			c.logger.Warn("cert snapshot unusable; starting cold", "err", err)
		case g != nil:
			loaded = g
			c.pool.Store(g)
			c.seq = g.seq
			c.persistedSeq = g.seq
			c.logger.Info("loaded last confirmed cert generation from snapshot",
				"entries", len(g.entries), "seq", g.seq)
		}
	}

	if err := c.refresh(ctx); err != nil {
		if status.Code(err) == codes.PermissionDenied {
			// BYOI / single-tenant edge: listing is refused by design. Keep
			// the historical behaviour exactly — serve certs provisioned
			// locally / via self-service ACME from an empty pool.
			c.logInitialFetchErr(err, "")
			c.pool.Store(emptyGeneration())
			loaded = nil
		} else if loaded != nil {
			c.logger.Warn("initial cert-svc fetch failed; serving last confirmed snapshot",
				"err", err, "entries", len(loaded.entries))
		} else {
			c.logInitialFetchErr(err, "")
			c.pool.Store(emptyGeneration())
		}
	}

	if c.bus != nil {
		if err := c.subscribeEvents(); err != nil {
			c.logger.Warn("cert push subscribe failed; falling back to poll-only",
				"err", err)
			opts.RefreshInterval = LegacyPollInterval
		} else {
			c.logger.Info("cert push subscribed (bff-edge mode)",
				"reconcile_interval", opts.RefreshInterval)
		}
	}
	c.startPoller(opts.RefreshInterval)
	return c, nil
}

// logInitialFetchErr logs a failed initial cert fetch at the right level.
// A BYOI / single-tenant edge is DENIED cert listing by design — bff-edge
// enforces org isolation and refuses ListCerts (it could otherwise leak
// another org's private key) — so that PermissionDenied is EXPECTED, not a
// problem. Log it at INFO so self-hosters aren't alarmed.
func (c *Client) logInitialFetchErr(err error, addr string) {
	if status.Code(err) == codes.PermissionDenied {
		c.logger.Info("cert-svc listing disabled for this edge (BYOI / single-tenant) — serving certs provisioned locally or via self-service ACME")
		return
	}
	c.logger.Warn("initial cert-svc fetch failed; serving with empty pool", "err", err, "addr", addr)
}

// startPoller runs the single goroutine that owns periodic reconciles,
// individual missing-cert retries, and out-of-band resync kicks.
func (c *Client) startPoller(interval time.Duration) {
	c.stopOnce = sync.OnceFunc(func() { close(c.stopCh) })
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		r := time.NewTicker(missingRetryInterval)
		defer r.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-t.C:
				c.pollerTurn(false)
			case <-c.kick:
				c.pollerTurn(false)
			case <-r.C:
				// Only wakes when a candidate is waiting on missing certs;
				// otherwise a no-op turn.
				c.pollerTurn(true)
			}
		}
	}()
}

// pollerTurn is one poller wakeup. retryOnly touches an armed incomplete
// candidate instead of doing a full reconcile.
func (c *Client) pollerTurn(retryOnly bool) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	if retryOnly {
		if c.pending == nil {
			return
		}
		if err := c.retryPending(ctx); err != nil {
			c.logger.Debug("missing cert retry still incomplete", "err", err)
		}
		return
	}
	if err := c.refresh(ctx); err != nil {
		if errors.Is(err, errIncompleteGeneration) {
			c.logger.Info("cert generation incomplete; active generation continues; missing certs retried",
				"retry_in", missingRetryInterval)
		} else {
			c.logger.Warn("cert refresh failed", "err", err)
		}
	}
	// A snapshot publish that failed on commit (or before this process
	// existed) is retried here without needing server data.
	c.repersistDirty()
}

// RequestResync asks for an immediate reconcile: used after a cert-event
// stream re-opens, and when a push fetch fails. Never blocks; coalesces.
func (c *Client) RequestResync() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// subscribeEvents wires the NATS cert.upsert / cert.delete handlers.
// Returns the first non-nil subscribe error; partial subscriptions are
// cleaned up so the caller can fall through to poll-only.
func (c *Client) subscribeEvents() error {
	up, err := c.bus.Subscribe(certevents.SubjectUpsertPrefix+">", c.onUpsert)
	if err != nil {
		return fmt.Errorf("subscribe upsert: %w", err)
	}
	del, err := c.bus.Subscribe(certevents.SubjectDeletePrefix+">", c.onDelete)
	if err != nil {
		_ = up.Drain()
		return fmt.Errorf("subscribe delete: %w", err)
	}
	c.upsert = up
	c.delete = del
	return nil
}

// onUpsert handles a single calabi.cert.upsert.<org> message: fetch the
// named cert and apply it as a one-entry delta generation.
//
// Idempotent: if the fingerprint named is already installed (NATS/bff
// redelivery), no RPC happens. A GetCert/parse failure changes NOTHING —
// the active generation keeps serving — and kicks a reconcile so the cert
// is picked up as soon as its key is available.
func (c *Client) onUpsert(m *eventbus.Msg) {
	var ev certevents.CertEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		c.logger.Warn("cert upsert: bad payload", "err", err, "subject", m.Subject)
		return
	}
	if ev.CertID <= 0 {
		return
	}
	if ev.Fingerprint != "" {
		if cur := c.pool.Load(); cur != nil {
			if _, ok := cur.fingerprintOwners[ev.Fingerprint]; ok {
				c.logger.Debug("cert upsert: fingerprint already in generation, skipping refetch",
					"cert_id", ev.CertID, "fp", ev.Fingerprint)
				return
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	got, err := c.rpc.GetCert(ctx, &pb.GetCertRequest{Id: ev.CertID, OrgId: ev.OrgID})
	if err != nil {
		c.logger.Warn("cert upsert: GetCert failed; active generation unchanged, scheduling reconcile",
			"err", err, "cert_id", ev.CertID)
		c.RequestResync()
		return
	}
	e, err := entryFromUpsert(&ev, got)
	if err != nil {
		c.logger.Warn("cert upsert: parse pair; active generation unchanged, scheduling reconcile",
			"err", err, "cert_id", ev.CertID)
		c.RequestResync()
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	cur := c.pool.Load()
	// Re-check under the lock: a concurrent commit may have installed it.
	if e.fingerprint != "" {
		if _, ok := cur.fingerprintOwners[e.fingerprint]; ok {
			return
		}
	}
	// A delete confirmed at a known watermark wins over an upsert at or
	// below it; an upsert that cannot prove it is newer (version 0) loses
	// to a confirmed delete too — an explicitly deleted id must not be
	// resurrected by unordered data.
	if tv, ok := cur.tombstones[e.id]; ok && (e.version == 0 || e.version <= tv) {
		c.logger.Info("cert upsert older than confirmed delete; ignored",
			"cert_id", e.id, "upsert_version", e.version, "deleted_version", tv)
		return
	}
	if prev, ok := cur.entries[e.id]; ok && prev.version > e.version {
		c.logger.Info("stale cert upsert; serving generation already newer; ignored",
			"cert_id", e.id, "have", prev.version, "got", e.version)
		return
	}
	entries := cloneEntries(cur.entries)
	tombstones := cloneTombstones(cur.tombstones)
	entries[e.id] = e
	// An upsert at or above the tombstone watermark is a re-created cert id;
	// the delete no longer applies.
	if _, tombstoned := tombstones[e.id]; tombstoned && e.version > 0 {
		delete(tombstones, e.id)
	}
	c.commitLocked(projectGeneration(c.nextSeqLocked(), entries, tombstones))
	c.logger.Info("cert generation updated via push",
		"cert_id", ev.CertID, "sans", e.sans, "seq", c.seq)
}

// onDelete applies a confirmed delete: the entry stops serving new
// handshakes in the NEXT committed generation, and a tombstone stops any
// stale listing from resurrecting it. In-flight handshakes already hold
// the old pointer and finish untouched. Idempotent over redelivery.
func (c *Client) onDelete(m *eventbus.Msg) {
	var ev certevents.CertEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		c.logger.Warn("cert delete: bad payload", "err", err, "subject", m.Subject)
		return
	}
	if ev.CertID <= 0 {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	cur := c.pool.Load()
	if tv, ok := cur.tombstones[ev.CertID]; ok && ev.Version > 0 && ev.Version <= tv {
		return // duplicate/redelivered delete at the same or older watermark
	}
	if _, present := cur.entries[ev.CertID]; !present && ev.Version <= 0 {
		// Nothing serving under that id and no watermark to fence with:
		// nothing to apply and nothing durable to record.
		return
	}
	entries := cloneEntries(cur.entries)
	tombstones := cloneTombstones(cur.tombstones)
	delete(entries, ev.CertID)
	if ev.Version > 0 {
		tombstones[ev.CertID] = ev.Version
	}
	c.commitLocked(projectGeneration(c.nextSeqLocked(), entries, tombstones))
	c.logger.Info("cert generation evicted via push",
		"cert_id", ev.CertID, "sans", ev.SANs, "seq", c.seq)
}

// refresh runs one full reconcile against the control plane:
//
//	ListCerts → compare the server generation digest → fetch EVERY listed
//	cert → commit a candidate generation.
//
// Fetching happens OUTSIDE writeMu so events keep landing; the commit
// re-merges under the lock with version fencing. Any missing cert aborts
// the commit (active generation stays serving) and arms pending retries.
func (c *Client) refresh(ctx context.Context) error {
	list, err := c.rpc.ListCerts(ctx, &pb.ListCertsRequest{OrgId: c.orgID})
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}
	metas := list.GetItems()
	digest := listingDigest(metas)
	asOf := listingAsOf(metas)
	if cur := c.pool.Load(); cur != nil && cur.digest == digest {
		// Same server generation already serving (a reconnect missed
		// nothing; a periodic poll found no change). Do not touch anything
		// — and certainly do not evict push-deltas a digest-less view might
		// have mishandled.
		return nil
	}
	got := make(map[int64]*certEntry, len(metas))
	missing := make(map[int64]struct{})
	var missingIDs []int64
	for _, meta := range metas {
		id := meta.GetMeta().GetId()
		entry, gerr := c.fetchEntry(ctx, meta)
		if gerr != nil {
			c.logger.Warn("cert candidate incomplete; entry withheld from new generation",
				"err", gerr, "id", id)
			missing[id] = struct{}{}
			missingIDs = append(missingIDs, id)
			continue
		}
		got[id] = entry
	}
	if len(missing) > 0 {
		// The OLD active generation keeps serving; retry the missing ids
		// alone rather than re-pulling everything every retry.
		c.armPending(metas, digest, asOf, got, missing)
		return fmt.Errorf("%w: %d cert(s) not fetched (e.g. id %d)",
			errIncompleteGeneration, len(missing), missingIDs[0])
	}
	c.commitListing(metas, digest, asOf, got)
	return nil
}

// fetchEntry pulls one listed cert and builds its immutable entry.
func (c *Client) fetchEntry(ctx context.Context, meta *pb.CertMeta) (*certEntry, error) {
	id := meta.GetMeta().GetId()
	got, err := c.rpc.GetCert(ctx, &pb.GetCertRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("get cert %d: %w", id, err)
	}
	tc, err := parsePair(got.GetFullchainPem(), got.GetPrivateKeyPem())
	if err != nil {
		return nil, fmt.Errorf("parse cert %d: %w", id, err)
	}
	return entryFromMeta(meta, got, tc), nil
}

// armPending records (or replaces) the incomplete candidate. A newer
// listing simply supersedes an older pending one.
func (c *Client) armPending(metas []*pb.CertMeta, digest string, asOf int64, got map[int64]*certEntry, missing map[int64]struct{}) {
	byID := make(map[int64]*pb.CertMeta, len(metas))
	for _, m := range metas {
		byID[m.GetMeta().GetId()] = m
	}
	c.pending = &pendingFetch{
		metas:   metas,
		byID:    byID,
		digest:  digest,
		asOf:    asOf,
		got:     got,
		missing: missing,
	}
}

// retryPending fetches just the missing ids of the armed candidate and
// commits once complete. A NotFound means the listing changed under us —
// discard the candidate and reconcile fresh.
func (c *Client) retryPending(ctx context.Context) error {
	p := c.pending
	if p == nil {
		return nil
	}
	resync := false
	for id := range p.missing {
		meta := p.byID[id]
		got, err := c.rpc.GetCert(ctx, &pb.GetCertRequest{Id: id})
		switch {
		case status.Code(err) == codes.NotFound:
			c.logger.Info("missing cert vanished server-side; reconciling fresh", "id", id)
			resync = true
		case err != nil:
			continue // still missing; try again next interval
		default:
			tc, perr := parsePair(got.GetFullchainPem(), got.GetPrivateKeyPem())
			if perr != nil {
				c.logger.Warn("retry: parse cert still failing", "err", perr, "id", id)
				continue
			}
			p.got[id] = entryFromMeta(meta, got, tc)
			delete(p.missing, id)
		}
	}
	if resync {
		c.pending = nil
		return c.refresh(ctx)
	}
	if len(p.missing) > 0 {
		return errIncompleteGeneration
	}
	c.pending = nil
	c.commitListing(p.metas, p.digest, p.asOf, p.got)
	return nil
}

// commitListing merges a fully-fetched listing candidate with the active
// generation under version fencing and commits. Callers must NOT hold
// writeMu; this takes it.
func (c *Client) commitListing(metas []*pb.CertMeta, digest string, asOf int64, fetched map[int64]*certEntry) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	cur := c.pool.Load()

	listed := make(map[int64]struct{}, len(metas))
	for _, m := range metas {
		listed[m.GetMeta().GetId()] = struct{}{}
	}

	entries := make(map[int64]*certEntry, len(fetched))
	tombstones := cloneTombstones(cur.tombstones)
	staleOmissions := 0
	// An EMPTY listing carries no as-of watermark, so "entry newer than
	// as-of" cannot distinguish a stale replica from an org that genuinely
	// has no certs. Keep the historical — authoritative — reading: an empty
	// listing evicts. Stale-push protection therefore applies to non-empty
	// listings only.
	nonEmptyListing := len(metas) > 0

	// Candidate entries win unless the active generation already serves a
	// strictly newer push, or a confirmed delete at >= watermark forbids
	// resurrection.
	for id, e := range fetched {
		if prev, ok := cur.entries[id]; ok && prev.version > e.version {
			entries[id] = prev // a push landed after this stale listing
			continue
		}
		if tv, tombstoned := cur.tombstones[id]; tombstoned {
			if e.version == 0 || e.version <= tv {
				// Confirmed delete still wins; a listing that still shows
				// the cert is stale relative to the delete.
				continue
			}
			delete(tombstones, id) // same id genuinely re-created later
		}
		entries[id] = e
	}
	// Entries the listing merely omits are normally evicted — the listing
	// is authoritative for scope and deletion. But against a NON-EMPTY
	// listing, a push-installed entry strictly NEWER than the listing as-of
	// could not have been known to this listing; retain it and reconcile
	// again promptly.
	if nonEmptyListing {
		for id, e := range cur.entries {
			if _, ok := entries[id]; ok {
				continue
			}
			if _, inList := listed[id]; inList {
				continue // withheld by the tombstone branch above
			}
			if e.version > 0 && e.version > asOf {
				entries[id] = e
				staleOmissions++
			}
		}
	}

	g := projectGeneration(c.nextSeqLocked(), entries, tombstones)
	c.commitLocked(g)
	c.pending = nil
	c.logger.Debug("cert generation reconciled from listing",
		"entries", len(entries), "snis", len(g.bySNI), "seq", c.seq,
		"stale_guards", staleOmissions, "digest", digest)
	if staleOmissions > 0 {
		// The listing was older than state we already serve: get a fresh
		// server generation as soon as the poller can.
		c.RequestResync()
	}
}

// commitLocked stores the generation and publishes its encrypted snapshot.
// Snapshot failure NEVER blocks or rolls back the in-memory generation:
// temp+rename guarantees the previous confirmed file is still on disk, and
// repersistDirty retries on the next poller turn.
// Caller holds writeMu.
func (c *Client) commitLocked(g *generation) {
	c.seq = g.seq
	c.pool.Store(g)
	if c.store == nil {
		c.persistedSeq = g.seq
		return
	}
	// Never seal a wholly-empty generation over a recoverable one (a
	// BYOI-style empty listing must not erase a restart fallback). A
	// generation carrying only tombstones IS persisted: after an offline
	// restart, a cert confirmed deleted must stay deleted.
	if len(g.entries) == 0 && len(g.tombstones) == 0 {
		return
	}
	if err := c.store.save(g); err != nil {
		c.logger.Warn("cert snapshot publish failed; previous snapshot retained; will retry",
			"err", err, "seq", g.seq)
		return
	}
	c.persistedSeq = g.seq
}

// repersistDirty re-publishes a generation whose snapshot write previously
// failed. Runs on the poller; needs no RPC.
func (c *Client) repersistDirty() {
	if c.store == nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	g := c.pool.Load()
	if g == nil || g.seq == c.persistedSeq || len(g.entries) == 0 {
		return
	}
	if err := c.store.save(g); err != nil {
		c.logger.Warn("cert snapshot republish still failing; previous snapshot retained",
			"err", err, "seq", g.seq)
		return
	}
	c.persistedSeq = g.seq
}

// nextSeqLocked returns the next local generation number. Caller holds
// writeMu (or runs in single-threaded construction).
func (c *Client) nextSeqLocked() uint64 {
	c.seq++
	return c.seq
}

func cloneEntries(in map[int64]*certEntry) map[int64]*certEntry {
	out := make(map[int64]*certEntry, len(in))
	for k, v := range in {
		out[k] = v // entries are immutable after construction
	}
	return out
}

func cloneTombstones(in map[int64]int64) map[int64]int64 {
	out := make(map[int64]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyInt64Map(in map[int64]int64) map[int64]int64 {
	if len(in) == 0 {
		return nil
	}
	return cloneTombstones(in)
}

func sortedInt64Keys[V any](m map[int64]V) []int64 {
	ids := make([]int64, 0, len(m))
	for k := range m {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// parsePair is tls.X509KeyPair with an emptiness check: an empty/missing
// cert is a fetch failure, not an entry serving nil.
func parsePair(fullchainPEM, privateKeyPEM []byte) (*tls.Certificate, error) {
	if len(fullchainPEM) == 0 || len(privateKeyPEM) == 0 {
		return nil, errors.New("empty cert or private key in response")
	}
	tc, err := tls.X509KeyPair(fullchainPEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &tc, nil
}

func normKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normSans(sans []string) []string {
	out := make([]string, 0, len(sans))
	for _, s := range sans {
		if k := normKey(s); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// entryFromMeta builds the immutable entry for a ListCerts item. The
// LISTING metadata (sans, subject, fingerprint, watermark) is
// authoritative for the digest; the PEM pair comes from GetCert.
func entryFromMeta(meta *pb.CertMeta, got *pb.GetCertResponse, tc *tls.Certificate) *certEntry {
	return &certEntry{
		id:            meta.GetMeta().GetId(),
		orgID:         meta.GetOrgId(),
		cert:          tc,
		sans:          normSans(meta.GetSans()),
		subject:       normKey(meta.GetSubject()),
		fingerprint:   strings.TrimSpace(meta.GetFingerprint()),
		version:       metaVersion(meta),
		fullchainPEM:  append([]byte(nil), got.GetFullchainPem()...),
		privateKeyPEM: append([]byte(nil), got.GetPrivateKeyPem()...),
	}
}

// entryFromUpsert builds the entry for a push event. The GetCert response
// carries the same CertMeta the listing would; fall back to the event
// payload when the server omits it.
func entryFromUpsert(ev *certevents.CertEvent, got *pb.GetCertResponse) (*certEntry, error) {
	tc, err := parsePair(got.GetFullchainPem(), got.GetPrivateKeyPem())
	if err != nil {
		return nil, err
	}
	var (
		orgID       = ev.OrgID
		sans        = normSans(ev.SANs)
		subject     = normKey(ev.Subject)
		fingerprint = strings.TrimSpace(ev.Fingerprint)
		version     = ev.Version
	)
	if m := got.GetCert(); m != nil {
		if m.GetOrgId() != 0 {
			orgID = m.GetOrgId()
		}
		if len(m.GetSans()) > 0 {
			sans = normSans(m.GetSans())
		}
		if s := normKey(m.GetSubject()); s != "" {
			subject = s
		}
		if fp := strings.TrimSpace(m.GetFingerprint()); fp != "" {
			fingerprint = fp
		}
		if v := metaVersion(m); v != 0 {
			version = v
		}
	}
	return &certEntry{
		id:            ev.CertID,
		orgID:         orgID,
		cert:          tc,
		sans:          sans,
		subject:       subject,
		fingerprint:   fingerprint,
		version:       version,
		fullchainPEM:  append([]byte(nil), got.GetFullchainPem()...),
		privateKeyPEM: append([]byte(nil), got.GetPrivateKeyPem()...),
	}, nil
}

// Close terminates the polling goroutine + cert-svc conn + NATS subs.
// Idempotent.
func (c *Client) Close() error {
	if c.upsert != nil {
		_ = c.upsert.Drain()
	}
	if c.delete != nil {
		_ = c.delete.Drain()
	}
	if c.stopOnce != nil {
		c.stopOnce()
	}
	return nil
}

// GetCertificate is the closure for tls.Config.GetCertificate.
//
// crypto/tls calls it once per incoming handshake with a populated
// ServerName; the returned *tls.Certificate is what THAT handshake uses —
// a later generation swap cannot affect a handshake already in flight.
func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	g := c.pool.Load()
	if g == nil {
		return nil, ErrNoCertForSNI
	}
	host := normKey(hello.ServerName)
	if cert, ok := g.bySNI[host]; ok {
		return cert, nil
	}
	// Wildcard fallback: if ClientHello asks for `foo.example.com`,
	// try `*.example.com` too.
	if i := strings.Index(host, "."); i > 0 {
		wild := "*" + host[i:]
		if cert, ok := g.bySNI[wild]; ok {
			return cert, nil
		}
	}
	return nil, ErrNoCertForSNI
}

// PoolSize is exposed for /metrics or debug pages.
func (c *Client) PoolSize() int {
	g := c.pool.Load()
	if g == nil {
		return 0
	}
	return len(g.bySNI)
}
