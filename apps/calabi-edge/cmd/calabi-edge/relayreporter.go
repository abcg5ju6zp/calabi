package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/calabinet/calabi/pkg/relay"
)

// relayUsageSubject is where a merged node re-sends its OWN relay usage. In
// cluster mode it lands on the real NATS (metering-svc consumes it directly); in
// BYOI/bff-edge mode the bffedgeclient bus maps it to the ReportRelayUsage RPC —
// there Publish only returns nil once the remote accepted, i.e. it IS the
// confirmation the reporter settles against.
const relayUsageSubject = "calabi.usage.relay"

// relayUsageMsg is the JSON shape on relayUsageSubject — matches
// metering-svc's RelayReport and calabi-coord's sink. ts is the unix minute the
// running total belongs to; metering-svc MAX-merges per (org, region, minute).
// Re-sending the SAME total for a minute is therefore idempotent: metering
// keeps the max and never double-charges, which is what makes every retry path
// below (failed send, restart recovery, shutdown tail) safe.
type relayUsageMsg struct {
	OrgID    int64  `json:"org_id"`
	Region   string `json:"region"`
	TS       int64  `json:"ts"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// relayUsagePendingFile is, under state.dir, the settlement journal of minutes
// metering has not confirmed. A single file rewritten whole (tmp+rename — see
// writeFileAtomic in relayadmission.go): publishing ticks once a minute and the
// bucket count is bounded by orgs × regions × unconfirmed minutes, so a tiny
// full rewrite is cheaper than any incremental format and a crash can never
// leave it half-written.
const relayUsagePendingFile = "relay-usage-pending.json"

const relayUsagePendingVersion = 1

// relayUsagePending is the on-disk shape of relayUsagePendingFile.
type relayUsagePending struct {
	Version int                  `json:"version"`
	Buckets []relayUsageOnDiskV1 `json:"buckets"`
}

// relayUsageOnDiskV1 is one unconfirmed (org, region, minute) running total.
type relayUsageOnDiskV1 struct {
	OrgID    int64  `json:"org_id"`
	Region   string `json:"region"`
	TS       int64  `json:"ts"` // unix minute the running total belongs to
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// usagePendingStore durably keeps the minutes metering has not confirmed yet.
// nil *usagePendingStore (no state.dir) disables disk recovery; the reporter
// then still retries within the process lifetime but cannot survive a restart.
type usagePendingStore struct {
	path   string
	logger *slog.Logger
}

func newUsagePendingStore(stateDir string, logger *slog.Logger) *usagePendingStore {
	dir := strings.TrimSpace(stateDir)
	if dir == "" {
		return nil
	}
	return &usagePendingStore{path: filepath.Join(dir, relayUsagePendingFile), logger: logger}
}

// save writes the whole pending set atomically, or removes the file once
// nothing is owed. Empty-or-absent after a clean settle is the normal state.
func (s *usagePendingStore) save(buckets []relayUsageOnDiskV1) error {
	if len(buckets) == 0 {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(relayUsagePending{Version: relayUsagePendingVersion, Buckets: buckets}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data)
}

// load returns the unconfirmed minutes a previous run left. A missing file is
// the normal first-boot case.
func (s *usagePendingStore) load() ([]relayUsageOnDiskV1, error) {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p relayUsagePending
	if uerr := json.Unmarshal(raw, &p); uerr != nil || p.Version != relayUsagePendingVersion {
		// tmp+rename writes mean a torn file is not expected, so a parse
		// failure is real corruption. Move it aside instead of silently
		// overwriting it on the next save — the bytes it named exist nowhere
		// else — and report the loss loudly.
		bad := fmt.Sprintf("%s.corrupt-%d", s.path, time.Now().UnixNano())
		reason := uerr
		if reason == nil {
			reason = fmt.Errorf("unsupported version %d", p.Version)
		}
		if rerr := os.Rename(s.path, bad); rerr != nil {
			s.logger.Error("relay usage: pending settlement file is unreadable and could not be moved aside",
				"file", s.path, "err", reason)
			return nil, reason
		}
		return nil, fmt.Errorf("relay usage pending file %q unreadable (moved aside to %q): %w", s.path, bad, reason)
	}
	return p.Buckets, nil
}

// relayUsageReporter accumulates a merged node's OWN relay bytes into per-(org,
// region, MINUTE) running totals and settles them with metering.
//
// Settlement, in order, for every batch drained from the hub:
//
//  1. Fold each attributed delta into the pending total for its ORIGINAL
//     minute (the drain's truncated minute). TakeUsage read-and-resets the hub
//     counters, so the moment a delta leaves the hub these bytes exist nowhere
//     else; folding into the in-memory pending map happens before anything that
//     can fail.
//  2. Persist the whole pending set to disk. Nothing is published while this
//     fails: bytes stay in memory and the write is retried next tick, so a
//     failure between hub drain and disk write cannot silently drop the zeroed
//     counters.
//  3. Publish every unconfirmed minute — the minute just folded plus any
//     earlier minute previous sends could not confirm (sends are retried across
//     the minute boundary instead of the rollover wiping them).
//  4. Settle only after the remote confirms: an acked OPEN minute is kept as
//     the cumulative base for later same-minute deltas (and flips back to
//     unconfirmed when new bytes arrive); an acked CLOSED minute is reclaimed.
//     metering MAX-merges per (org, region, minute), so any duplicate produced
//     by a crash between publish and reclaim, or by a restart that reloaded the
//     file, overwrites with an equal value and never double-charges.
//
// A zero-traffic tick with everything already confirmed publishes nothing,
// exactly as before.
//
// classify maps one drained delta to the (org, region) it is billed under, or
// ok=false to drop it. That one function is the whole difference between a
// self-hosted relay (single-tenant: every delta → the node's org, a "self-<label>"
// region excluded from the cap) and a platform relay (multi-tenant: each delta →
// the meshnet its grant proved, a plain region counted toward the cap; bytes with
// no grant are unattributable and dropped rather than misbilled).
//
// Core type: it publishes through the usagePublisher INTERFACE below (real NATS
// in cluster mode, the bff-edge-backed bus in BYOI mode) and imports no platform
// package, so it stays on the edge's ciphertext-only side.
// usagePublisher is the ONE method this reporter needs from the event bus.
// Declared locally rather than importing pkg/eventbus: that package carries the
// platform's NATS subject names and payload shapes and must never reach the
// public tree, while this file is core and
// ships. eventbus.Bus satisfies it structurally, so the platform wiring passes
// its bus unchanged.
type usagePublisher interface {
	Publish(subject string, payload []byte) error
}

type relayUsageReporter struct {
	bus      usagePublisher
	classify func(relay.UsageDelta) (org int64, region string, ok bool)
	logger   *slog.Logger
	store    *usagePendingStore // nil: no state.dir, retries are in-memory only

	mu sync.Mutex
	// pending holds every (minute, org, region) running total metering has not
	// confirmed. The current minute accumulates here; past minutes linger ONLY
	// until a (re-)publish is acknowledged, so a failed send across a minute
	// boundary keeps being retried rather than being wiped by the rollover.
	pending map[usageBucketKey]*usageAccum
}

type usageBucketKey struct {
	minute int64
	org    int64
	region string
}

type usageAccum struct {
	in, out uint64
	// confirmed says the CURRENT running total was accepted by metering. It is
	// kept, not deleted, while the minute is open because later deltas in the
	// same minute must still publish as a CUMULATIVE total (a metering MAX-merge
	// of a smaller value could otherwise lose bytes). New bytes flip it back to
	// false; the rollover into a later minute reclaims it. Ephemeral — anything
	// reloaded from disk starts unconfirmed and is simply re-sent.
	confirmed bool
}

// newRelayUsageReporter builds a SELF-HOSTED reporter: every delta is billed to
// the one fixed org under a fixed "self-<label>" region. The org is 0 for a BYOI
// node in bff-edge mode (bff-edge stamps it from the mTLS cert) and the cluster
// fallback otherwise. Attribution needs no grant here — a single-tenant relay's
// traffic is all one org's by construction.
func newRelayUsageReporter(bus usagePublisher, orgID int64, region, stateDir string, logger *slog.Logger) *relayUsageReporter {
	return newRelayUsageReporterWithStore(bus, func(relay.UsageDelta) (int64, string, bool) {
		return orgID, region, true
	}, stateDir, logger)
}

// newPlatformRelayUsageReporter builds a PLATFORM reporter: it serves many orgs,
// so each delta is billed to the meshnet its grant proved, under the platform
// region code. A delta with meshnet 0 (auth off / no grant) is unattributable
// and dropped — misbilling it to a wrong or zero org is worse than not counting it.
func newPlatformRelayUsageReporter(bus usagePublisher, region, stateDir string, logger *slog.Logger) *relayUsageReporter {
	return newRelayUsageReporterWithStore(bus, func(d relay.UsageDelta) (int64, string, bool) {
		if d.Meshnet == 0 {
			return 0, "", false
		}
		return d.Meshnet, region, true
	}, stateDir, logger)
}

func newRelayUsageReporterWithStore(bus usagePublisher, classify func(relay.UsageDelta) (int64, string, bool), stateDir string, logger *slog.Logger) *relayUsageReporter {
	r := &relayUsageReporter{
		bus:      bus,
		classify: classify,
		logger:   logger,
		store:    newUsagePendingStore(stateDir, logger),
		pending:  make(map[usageBucketKey]*usageAccum),
	}
	if r.store == nil {
		// No state.dir means no cross-restart recovery: every failure mode the
		// disk journal covers (publish failure, exit-time tail flush failure)
		// degrades back to loss-on-exit. Say it once rather than silently.
		logger.Warn("relay usage: no state.dir; usage still retries within this process, but unconfirmed minutes are lost if it exits")
	}
	r.recover()
	return r
}

// recover loads the minutes a previous run never got confirmed and parks them
// in pending; reportLoop re-sends them on startup. The bytes on disk are
// already final per minute, and the resend is MAX-idempotent, so no merge with
// later traffic is needed.
func (r *relayUsageReporter) recover() {
	if r.store == nil {
		return
	}
	buckets, err := r.store.load()
	if err != nil {
		r.logger.Error("relay usage: could not load unconfirmed minutes from the previous run", "err", err)
		return
	}
	if len(buckets) == 0 {
		return
	}
	r.mu.Lock()
	for _, b := range buckets {
		if b.TS <= 0 || (b.BytesIn == 0 && b.BytesOut == 0) {
			continue
		}
		k := usageBucketKey{minute: b.TS, org: b.OrgID, region: b.Region}
		a := r.pending[k]
		if a == nil {
			a = &usageAccum{}
			r.pending[k] = a
		}
		a.in += b.BytesIn
		a.out += b.BytesOut
	}
	n := len(r.pending)
	r.mu.Unlock()
	r.logger.Warn("relay usage: recovered unconfirmed minutes from the previous run; they will be re-sent (metering max-merges per org/region/minute, so a duplicate never double-charges)",
		"buckets", n)
}

// record settles one hub drain: fold into the minute's pending totals, persist
// anything that changed, then publish every unconfirmed minute. A zero-traffic
// tick that leaves everything confirmed returns without publishing — the
// steady-state cadence is unchanged; an unconfirmed OLD minute is still retried
// on a tick carrying no new bytes.
func (r *relayUsageReporter) record(deltas []relay.UsageDelta, now time.Time) {
	minute := now.UTC().Truncate(time.Minute).Unix()
	// 1) Fold first. TakeUsage zeroed the hub counters, so these bytes exist
	// nowhere else from here on and must land in our map before any I/O. The
	// same pass reclaims prior minutes the remote already confirmed.
	folded, pruned := r.fold(deltas, minute)
	// 2) Durable before remote. New totals MUST be on disk before they are
	// published: a failed write keeps the bytes in memory (and the previous
	// file on disk) and withholds this tick's sends — the next drain retries.
	// A failed PRUNE is only housekeeping (its stale minutes resend MAX-safely
	// after a restart), so it must not block the current minute's sends.
	if folded > 0 || pruned > 0 {
		if ok := r.persist(); !ok && folded > 0 {
			return
		}
	}
	// 3) Publish the minute just folded AND any older unconfirmed minute; the
	// current minute is marked confirmed on ack (kept as the cumulative base),
	// a closed minute is reclaimed.
	if r.unconfirmedCount() > 0 {
		r.flush(minute)
	}
}

// fold attributes and accumulates one drained batch into the current minute's
// buckets, and reclaims CONFIRMED buckets of minutes that have since closed —
// their totals are final and settled, whereas an unconfirmed past minute must
// stay for retry across the boundary. Growing a confirmed bucket makes its new
// total unconfirmed again. It returns how many deltas were attributed and how
// many closed-minute buckets were reclaimed.
func (r *relayUsageReporter) fold(deltas []relay.UsageDelta, minute int64) (folded, pruned int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.pending {
		if k.minute < minute && b.confirmed {
			delete(r.pending, k)
			pruned++
		}
	}
	for _, d := range deltas {
		if d.BytesIn == 0 && d.BytesOut == 0 {
			continue
		}
		org, region, ok := r.classify(d)
		if !ok {
			continue
		}
		k := usageBucketKey{minute: minute, org: org, region: region}
		b := r.pending[k]
		if b == nil {
			b = &usageAccum{}
			r.pending[k] = b
		}
		b.in += d.BytesIn
		b.out += d.BytesOut
		b.confirmed = false
		folded++
	}
	return folded, pruned
}

// unconfirmedCount is how many buckets still need a (re-)send.
func (r *relayUsageReporter) unconfirmedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.pending {
		if !b.confirmed {
			n++
		}
	}
	return n
}

// persist writes the whole pending set durably. A failure leaves the bytes
// retryable in memory and on the previous on-disk file; callers must not
// publish until it succeeds.
func (r *relayUsageReporter) persist() bool {
	if r.store == nil {
		return true
	}
	buckets := r.snapshotLocked()
	if err := r.store.save(buckets); err != nil {
		r.logger.Error("relay usage: cannot persist pending settlement state; keeping the drained bytes in memory and withholding publishes until the write succeeds",
			"file", r.store.path, "buckets", len(buckets), "err", err)
		return false
	}
	return true
}

// flush publishes every unconfirmed bucket, oldest minute first. curMinute is
// the drain's minute: an acked bucket OF that minute stays in pending marked
// confirmed as the cumulative base (later same-minute deltas still publish as a
// running total); an acked bucket of a CLOSED minute is finally reclaimed.
// curMinute 0 (startup recovery) treats every recovered bucket as closed.
// One RPC failing does not block the others; its minute simply stays
// unconfirmed (memory + disk) for the next drain to resend.
func (r *relayUsageReporter) flush(curMinute int64) {
	type item struct {
		k       usageBucketKey
		in, out uint64
	}
	r.mu.Lock()
	items := make([]item, 0, len(r.pending))
	for k, a := range r.pending {
		if !a.confirmed {
			items = append(items, item{k: k, in: a.in, out: a.out})
		}
	}
	r.mu.Unlock()
	slices.SortFunc(items, func(a, b item) int {
		if c := cmp.Compare(a.k.minute, b.k.minute); c != 0 {
			return c
		}
		if c := cmp.Compare(a.k.org, b.k.org); c != 0 {
			return c
		}
		return cmp.Compare(a.k.region, b.k.region)
	})

	reclaimed := 0
	for _, it := range items {
		payload, err := json.Marshal(relayUsageMsg{
			OrgID: it.k.org, Region: it.k.region, TS: it.k.minute,
			BytesIn: clampU64(it.in), BytesOut: clampU64(it.out),
		})
		if err != nil {
			continue // unreachable for these field types; left unconfirmed and retried
		}
		if err := r.bus.Publish(relayUsageSubject, payload); err != nil {
			// Unconfirmed: do not reclaim. The minute is on disk already and is
			// re-sent with the next drain, across any minute boundary.
			r.logger.Warn("relay usage publish failed; the minute stays pending and will be re-sent",
				"org", it.k.org, "region", it.k.region, "ts", it.k.minute, "err", err)
			continue
		}
		r.mu.Lock()
		if curMinute != 0 && it.k.minute == curMinute {
			// Open minute: keep the total as the base the next same-minute
			// drain accumulates onto.
			r.pending[it.k].confirmed = true
		} else {
			delete(r.pending, it.k)
			reclaimed++
		}
		r.mu.Unlock()
	}
	if reclaimed == 0 || r.store == nil {
		return
	}
	// Best-effort journal pruning of closed-and-settled minutes. A failure
	// leaves them on disk: the next start re-sends them and metering's
	// MAX-merge makes the duplicate harmless, while the live map dropped them.
	if err := r.store.save(r.snapshotLocked()); err != nil {
		r.logger.Warn("relay usage: confirmed minutes could not be pruned from the pending file; a restart re-sends them harmlessly", "err", err)
	}
}

// retryPending re-sends everything still pending without folding new bytes. It
// is the startup-recovery kick, so a restart does not wait up to a minute for
// the first tick before settling an old minute.
func (r *relayUsageReporter) retryPending() {
	r.mu.Lock()
	n := len(r.pending)
	r.mu.Unlock()
	if n > 0 {
		r.flush(0)
	}
}

// snapshotLocked returns a deterministically ordered copy of pending for disk.
func (r *relayUsageReporter) snapshotLocked() []relayUsageOnDiskV1 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]relayUsageOnDiskV1, 0, len(r.pending))
	for k, a := range r.pending {
		out = append(out, relayUsageOnDiskV1{
			OrgID: k.org, Region: k.region, TS: k.minute,
			BytesIn: a.in, BytesOut: a.out,
		})
	}
	slices.SortFunc(out, func(a, b relayUsageOnDiskV1) int {
		if c := cmp.Compare(a.TS, b.TS); c != 0 {
			return c
		}
		if c := cmp.Compare(a.OrgID, b.OrgID); c != 0 {
			return c
		}
		return cmp.Compare(a.Region, b.Region)
	})
	return out
}

// reportLoop drains the hub and reports the running total once a minute,
// matching metering-svc's per-minute buckets. On shutdown it books the tail
// through the same persist→publish path: if that final RPC cannot complete, the
// minute is already on disk and the next run settles it.
func (r *relayUsageReporter) reportLoop(ctx context.Context, take func() []relay.UsageDelta) {
	// Settle what the previous run left unconfirmed at once rather than after a
	// full minute.
	r.retryPending()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.record(take(), time.Now())
			return
		case <-t.C:
			r.record(take(), time.Now())
		}
	}
}

// clampU64 caps a byte count at the int64 range. Relay bytes per minute never
// approach this; the guard only avoids a wrap-around from a bug upstream.
func clampU64(v uint64) int64 {
	const max = int64(1) << 62
	if v > uint64(max) {
		return max
	}
	return int64(v)
}
