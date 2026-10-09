package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/relay"
)

type fakeBus struct {
	mu        sync.Mutex
	published [][]byte
	// failNext is how many upcoming Publish calls fail. The attempt is still
	// recorded, so assertions can see exactly what went on the wire.
	failNext int
}

var errFakePublish = errors.New("fake publish failure")

func (f *fakeBus) Publish(_ string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), payload...)
	f.published = append(f.published, cp)
	if f.failNext > 0 {
		f.failNext--
		return errFakePublish
	}
	return nil
}

// failPublishes arms the next n Publish calls to fail.
func (f *fakeBus) failPublishes(n int) {
	f.mu.Lock()
	f.failNext = n
	f.mu.Unlock()
}

// Publish is the whole interface now: the reporter takes usagePublisher, not
// eventbus.Bus, so this file links no platform transport package either — the
// export would otherwise pull pkg/eventbus back in through the TEST deps.

func (f *fakeBus) msgs(t *testing.T) []relayUsageMsg {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]relayUsageMsg, 0, len(f.published))
	for _, p := range f.published {
		var m relayUsageMsg
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("bad payload: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// The reporter re-sends the RUNNING TOTAL for the current minute (metering-svc
// MAX-merges per minute), and a confirmed minute is reclaimed. Getting this
// wrong either loses bytes (publishing raw deltas that overwrite) or
// double-counts.
func TestRelayUsageReporter_RunningTotalPerMinute(t *testing.T) {
	fb := &fakeBus{}
	r := newRelayUsageReporter(fb, 7, "self-hk-1", "", slog.Default())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{{BytesIn: 100, BytesOut: 10}}, t0)
	r.record([]relay.UsageDelta{{BytesIn: 50, BytesOut: 5}}, t0.Add(20*time.Second)) // same minute
	r.record([]relay.UsageDelta{{BytesIn: 3, BytesOut: 1}}, t0.Add(70*time.Second))  // next minute
	r.record(nil, t0.Add(80*time.Second))                                            // empty drain → no publish

	m := fb.msgs(t)
	if len(m) != 3 {
		t.Fatalf("published %d msgs, want 3 (empty drain must not publish)", len(m))
	}
	// Same minute: second publish carries the ACCUMULATED running total.
	want := []struct {
		in, out int64
	}{{100, 10}, {150, 15}, {3, 1}}
	for i, w := range want {
		if m[i].OrgID != 7 || m[i].Region != "self-hk-1" {
			t.Errorf("msg[%d] org/region = %d/%q, want 7/self-hk-1", i, m[i].OrgID, m[i].Region)
		}
		if m[i].BytesIn != w.in || m[i].BytesOut != w.out {
			t.Errorf("msg[%d] = %d/%d, want %d/%d", i, m[i].BytesIn, m[i].BytesOut, w.in, w.out)
		}
	}
	if m[0].TS != m[1].TS {
		t.Errorf("same-minute publishes have different ts: %d vs %d", m[0].TS, m[1].TS)
	}
	if m[0].TS == m[2].TS {
		t.Errorf("different minutes share ts %d — reset did not change the minute key", m[0].TS)
	}
}

// A platform relay serves many orgs at once: each delta is billed to the meshnet
// its grant proved, one running total PER (org, region). A delta with no meshnet
// (auth off / no grant) is unattributable and must be dropped, not misbilled.
func TestPlatformRelayUsageReporter_PerOrg(t *testing.T) {
	fb := &fakeBus{}
	r := newPlatformRelayUsageReporter(fb, "lax", "", slog.Default())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{
		{Meshnet: 1, BytesIn: 100, BytesOut: 10},
		{Meshnet: 2, BytesIn: 200, BytesOut: 20},
		{Meshnet: 0, BytesIn: 999, BytesOut: 99}, // no grant → unattributable → dropped
	}, t0)

	m := fb.msgs(t)
	if len(m) != 2 {
		t.Fatalf("published %d msgs, want 2 (org 0 must drop)", len(m))
	}
	byOrg := map[int64]relayUsageMsg{}
	for _, x := range m {
		byOrg[x.OrgID] = x
	}
	if _, leaked := byOrg[0]; leaked {
		t.Error("unattributable (meshnet 0) bytes were published")
	}
	if g := byOrg[1]; g.Region != "lax" || g.BytesIn != 100 || g.BytesOut != 10 {
		t.Errorf("org1 = %+v, want region lax 100/10", g)
	}
	if g := byOrg[2]; g.Region != "lax" || g.BytesIn != 200 || g.BytesOut != 20 {
		t.Errorf("org2 = %+v, want region lax 200/20", g)
	}
	if byOrg[1].TS != byOrg[2].TS {
		t.Errorf("same-tick orgs got different ts: %d vs %d", byOrg[1].TS, byOrg[2].TS)
	}

	// Next minute for org 1 only: its bucket is a fresh minute (not a running
	// total across the boundary), and org 2 — silent this minute, and already
	// confirmed — is not re-published.
	r.record([]relay.UsageDelta{{Meshnet: 1, BytesIn: 5, BytesOut: 1}}, t0.Add(70*time.Second))
	m = fb.msgs(t)
	last := m[len(m)-1]
	if last.OrgID != 1 || last.BytesIn != 5 || last.BytesOut != 1 {
		t.Errorf("post-rollover publish = %+v, want org1 5/1 (fresh minute, not accumulated)", last)
	}
	if len(m) != 3 {
		t.Errorf("published %d total, want 3 (org2 not re-sent on a minute it had no traffic)", len(m))
	}
}

// A failed publish must not lose the minute: the rollover into the next minute
// must not wipe it, and the next drain re-sends the OLD minute (under its
// original ts) alongside the new one, oldest first. metering MAX-merges, so the
// repeated equal total never double-charges.
func TestRelayUsageReporter_FailedPublishResendsOldMinuteAcrossBoundary(t *testing.T) {
	fb := &fakeBus{}
	fb.failPublishes(1) // the old minute's first send fails
	r := newRelayUsageReporter(fb, 7, "self-hk-1", "", slog.Default())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{{BytesIn: 100, BytesOut: 10}}, t0)
	if m := fb.msgs(t); len(m) != 1 || m[0].TS != t0.Truncate(time.Minute).Unix() {
		t.Fatalf("first (failed) attempt = %+v, want one send for minute %d", m, t0.Truncate(time.Minute).Unix())
	}

	// New minute: the failed old minute must be re-sent FIRST, then the new one.
	r.record([]relay.UsageDelta{{BytesIn: 5, BytesOut: 1}}, t0.Add(70*time.Second))
	m := fb.msgs(t)
	if len(m) != 3 {
		t.Fatalf("published %d msgs, want 3 (failed attempt + old-minute resend + new minute)", len(m))
	}
	oldMinute, newMinute := t0.Truncate(time.Minute).Unix(), t0.Add(70*time.Second).Truncate(time.Minute).Unix()
	if m[1].TS != oldMinute || m[1].BytesIn != 100 || m[1].BytesOut != 10 {
		t.Errorf("old-minute resend = %+v, want ts %d 100/10", m[1], oldMinute)
	}
	if m[2].TS != newMinute || m[2].BytesIn != 5 || m[2].BytesOut != 1 {
		t.Errorf("new-minute publish = %+v, want ts %d 5/1", m[2], newMinute)
	}
}

// Minutes the previous run could not confirm are recovered from state.dir and
// re-sent on startup; once acknowledged they are pruned from disk, so a further
// restart has nothing to resend.
func TestRelayUsageReporter_RestartRecoversPendingMinutesFromDisk(t *testing.T) {
	dir := t.TempDir()
	log := quietLog()
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)
	pendingPath := filepath.Join(dir, relayUsagePendingFile)

	// Previous run: every publish fails (including its shutdown tail flush).
	dead := &fakeBus{}
	dead.failPublishes(1 << 20)
	r1 := newRelayUsageReporter(dead, 7, "self-hk-1", dir, log)
	r1.record([]relay.UsageDelta{{BytesIn: 100, BytesOut: 10}}, t0)
	r1.record([]relay.UsageDelta{{BytesIn: 50, BytesOut: 5}}, t0.Add(20*time.Second)) // same minute, accumulates
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("unconfirmed minutes were not kept on disk: %v", err)
	}
	var saved relayUsagePending
	if raw, err := os.ReadFile(pendingPath); err != nil {
		t.Fatalf("read pending file: %v", err)
	} else if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("pending file is not valid JSON: %v", err)
	}
	if len(saved.Buckets) != 1 || saved.Buckets[0].BytesIn != 150 || saved.Buckets[0].BytesOut != 15 ||
		saved.Buckets[0].TS != t0.Truncate(time.Minute).Unix() {
		t.Fatalf("pending file = %+v, want one bucket 150/15 at the original minute", saved.Buckets)
	}

	// Restart with a healthy remote: the recovered minute goes out at once.
	alive := &fakeBus{}
	r2 := newRelayUsageReporter(alive, 7, "self-hk-1", dir, log)
	r2.retryPending()
	m := alive.msgs(t)
	if len(m) != 1 || m[0].TS != t0.Truncate(time.Minute).Unix() || m[0].BytesIn != 150 || m[0].BytesOut != 15 {
		t.Fatalf("recovered resend = %+v, want one 150/15 message at the old minute", m)
	}
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("confirmed minute was not pruned from disk (stat err=%v)", err)
	}

	// A further restart finds nothing owed, and a zero-traffic drain publishes
	// nothing: a confirmed minute is never re-sent.
	r3 := newRelayUsageReporter(&fakeBus{}, 7, "self-hk-1", dir, log)
	r3.record(nil, t0.Add(5*time.Minute))
	if n := len(r3.snapshotLocked()); n != 0 {
		t.Errorf("clean restart left %d pending buckets, want 0", n)
	}
}

// Between the hub drain (which zeroes the counters) and the disk write, a
// failure must not silently drop those bytes — and must not publish them
// non-durably either. They stay in memory; once the disk works again the
// accumulated total (earlier + later batch) is persisted and published once.
func TestRelayUsageReporter_DiskWriteFailureKeepsDrainedBytes(t *testing.T) {
	log := quietLog()
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	// A regular FILE where the store expects a directory makes every write fail
	// at MkdirAll; the pending journal can never be created under it.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fb := &fakeBus{}
	r := newRelayUsageReporter(fb, 7, "self-hk-1", blocked, log)

	r.record([]relay.UsageDelta{{BytesIn: 100, BytesOut: 10}}, t0)
	if n := len(fb.msgs(t)); n != 0 {
		t.Errorf("published %d messages despite the failed disk write; nothing non-durable may be sent", n)
	}
	if n := len(r.snapshotLocked()); n != 1 {
		t.Errorf("drained bytes vanished on disk failure: %d pending buckets, want 1", n)
	}

	// Repair the path and drain a second batch in the SAME minute: the first
	// batch must still be there, accumulated into the running total.
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	r.record([]relay.UsageDelta{{BytesIn: 50, BytesOut: 5}}, t0.Add(20*time.Second))
	m := fb.msgs(t)
	if len(m) != 1 || m[0].BytesIn != 150 || m[0].BytesOut != 15 || m[0].TS != t0.Truncate(time.Minute).Unix() {
		t.Fatalf("publish after disk recovery = %+v, want one 150/15 message at the original minute", m)
	}
}

// Unattributable platform bytes (and the self-hosted fixed identity) survive
// the persistence path unchanged: the disk bucket carries exactly what the
// classifier billed.
func TestPlatformRelayUsageReporter_PersistsAttributedBuckets(t *testing.T) {
	dir := t.TempDir()
	fb := &fakeBus{}
	fb.failPublishes(1 << 20) // force buckets to linger on disk
	r := newPlatformRelayUsageReporter(fb, "lax", dir, quietLog())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{
		{Meshnet: 1, BytesIn: 100, BytesOut: 10},
		{Meshnet: 0, BytesIn: 999, BytesOut: 99}, // dropped, never persisted
	}, t0)

	saved := r.snapshotLocked()
	if len(saved) != 1 {
		t.Fatalf("persisted %d buckets, want 1: %+v", len(saved), saved)
	}
	b := saved[0]
	if b.OrgID != 1 || b.Region != "lax" || b.BytesIn != 100 || b.BytesOut != 10 || b.TS != t0.Truncate(time.Minute).Unix() {
		t.Errorf("persisted bucket = %+v, want org1/lax 100/10 at the drain minute", b)
	}
}
