package configclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// ---------- scripted bidirectional stream ----------

type fakeStream struct {
	grpc.ClientStream
	rpc *fakeRPC
	ctx context.Context
	q   chan *pb.ConfigMessage
}

func (f *fakeStream) Send(m *pb.EdgeMessage) error { return f.rpc.deliver(m) }

func (f *fakeStream) Recv() (*pb.ConfigMessage, error) {
	select {
	case m, ok := <-f.q:
		if ok {
			return m, nil
		}
		// Queue drained: simulate the stream breaking so runOnce ends and
		// reconnects (as a real network interruption would).
		return nil, errStreamGone
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeStream) CloseSend() error         { return nil }
func (f *fakeStream) Context() context.Context { return f.ctx }

var errStreamGone = errors.New("stream gone")
var errNoMoreScripts = errors.New("no more scripted streams")

type fakeRPC struct {
	t *testing.T

	mu         sync.Mutex
	script     [][]*pb.ConfigMessage
	attempt    int
	hellos     []*pb.HelloEdge
	acks       []*pb.Ack
	beats      int
	sends      []*pb.EdgeMessage
	failOnSend map[int]bool // 1-based global send index that must error
}

func (r *fakeRPC) deliver(m *pb.EdgeMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := len(r.sends) + 1
	r.sends = append(r.sends, m)
	switch k := m.GetKind().(type) {
	case *pb.EdgeMessage_Hello:
		r.hellos = append(r.hellos, k.Hello)
	case *pb.EdgeMessage_Ack:
		r.acks = append(r.acks, k.Ack)
	case *pb.EdgeMessage_Beat:
		r.beats++
	}
	if r.failOnSend[idx] {
		return errors.New("send failed")
	}
	return nil
}

func (r *fakeRPC) Subscribe(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], error) {
	r.mu.Lock()
	idx := r.attempt
	r.attempt++
	if idx >= len(r.script) {
		r.mu.Unlock()
		return nil, errNoMoreScripts
	}
	msgs := r.script[idx]
	r.mu.Unlock()

	q := make(chan *pb.ConfigMessage, len(msgs))
	for _, m := range msgs {
		q <- m
	}
	close(q)
	return &fakeStream{rpc: r, ctx: ctx, q: q}, nil
}

func (r *fakeRPC) snapshot() (hellos []*pb.HelloEdge, acks []*pb.Ack, beats int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*pb.HelloEdge(nil), r.hellos...), append([]*pb.Ack(nil), r.acks...), r.beats
}

// ---------- scripted applier ----------

type scriptedApplier struct {
	mu            sync.Mutex
	snapshots     [][]Route
	local         []Delta
	remote        []Delta
	failLocalSeq  map[uint64]int // delta JSON id -> remaining forced failures
	failSnapshots int
}

func (a *scriptedApplier) OnSnapshot(routes []Route) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshots = append(a.snapshots, routes)
	if a.failSnapshots > 0 {
		a.failSnapshots--
		return errors.New("snapshot boom")
	}
	return nil
}

func (a *scriptedApplier) OnLocalDelta(d Delta) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.local = append(a.local, d)
	if a.failLocalSeq != nil && a.failLocalSeq[d.ID] > 0 {
		a.failLocalSeq[d.ID]--
		return errors.New("local apply boom")
	}
	return nil
}

func (a *scriptedApplier) OnRemoteDelta(d Delta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.remote = append(a.remote, d)
}

func (a *scriptedApplier) counts() (snaps, local, remote int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.snapshots), len(a.local), len(a.remote)
}

// ---------- builders ----------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startClient(t *testing.T, rpc *fakeRPC, ap Applier, cursorPath string) (*Client, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c, err := StartWithClient(ctx, testLogger(), rpc, Options{
		EdgeNodeID: 100, Applier: ap, CursorPath: cursorPath,
		MinBackoff: time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatalf("StartWithClient: %v", err)
	}
	return c, cancel
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func envSnapshotMsg(sha string, gen uint64, routes ...Route) *pb.ConfigMessage {
	body, _ := json.Marshal(snapshotEnvelope{Generation: gen, Routes: routes})
	return &pb.ConfigMessage{Kind: &pb.ConfigMessage_Snapshot{
		Snapshot: &pb.Snapshot{Sha: sha, BodyJson: body},
	}}
}

func bareSnapshotMsg(sha string, routes ...Route) *pb.ConfigMessage {
	body, _ := json.Marshal(routes)
	return &pb.ConfigMessage{Kind: &pb.ConfigMessage_Snapshot{
		Snapshot: &pb.Snapshot{Sha: sha, BodyJson: body},
	}}
}

func deltaMsg(wireID string, d Delta, parentSHA string) *pb.ConfigMessage {
	body, _ := json.Marshal(d)
	return &pb.ConfigMessage{Kind: &pb.ConfigMessage_Delta{
		Delta: &pb.Delta{DeltaId: wireID, ParentSha: parentSHA, PatchJson: body},
	}}
}

func malformedDeltaMsg(wireID string) *pb.ConfigMessage {
	return &pb.ConfigMessage{Kind: &pb.ConfigMessage_Delta{
		Delta: &pb.Delta{DeltaId: wireID, PatchJson: []byte("{bad")},
	}}
}

func heartbeatMsg() *pb.ConfigMessage { return &pb.ConfigMessage{} }

func testRoute(id int, edge int64, port int32, kind string, clientID int64) Route {
	return Route{ID: id, Name: kind + "-route", Type: kind, RemotePort: port,
		EdgeNodeID: edge, ClientID: clientID, Domain: "x.example"}
}

func upsertDelta(seq uint64, r Route) Delta { return Delta{ID: seq, Kind: "upsert", Route: r} }

// ---------- tests ----------

func TestFirstConnectSendsEmptyCursorAndAppliesSnapshot(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{bareSnapshotMsg("sha-a", testRoute(1, 100, 0, "http", 7))},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "snapshot applied", func() bool { snaps, _, _ := ap.counts(); return snaps == 1 })
	hellos, _, _ := rpc.snapshot()
	if len(hellos) == 0 || hellos[0].GetEdgeNodeId() != 100 {
		t.Fatalf("hello not sent as edge 100: %+v", hellos)
	}
	if hellos[0].GetCurrentSnapshotSha() != "" {
		t.Fatalf("first connection must send empty sha to force full snapshot, got %q",
			hellos[0].GetCurrentSnapshotSha())
	}
}

func TestDeltaAckedOnlyAfterApplyAndCursorAdvances(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			deltaMsg("d1", upsertDelta(1, testRoute(1, 100, 20001, "tcp", 7)), "sha-a"),
		},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "delta applied + acked", func() bool {
		_, acks, _ := rpc.snapshot()
		return len(acks) == 1
	})
	_, acks, _ := rpc.snapshot()
	if !acks[0].GetOk() || acks[0].GetDeltaId() != "d1" {
		t.Fatalf("want ok ack for d1, got %+v", acks[0])
	}
	cur := c.ConfirmedCursor()
	if cur.SnapshotSHA != "sha-a" || cur.Seq != 1 || cur.DeltaID != "d1" {
		t.Fatalf("cursor = %+v, want {sha-a 1 d1}", cur)
	}
}

func TestRemoteDeltaAdvancesGenerationButNeverHitsLocal(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			deltaMsg("d1", upsertDelta(1, testRoute(1, 200, 0, "http", 7)), "sha-a"),
			deltaMsg("d2", upsertDelta(2, testRoute(2, 100, 0, "http", 7)), "sha-a"),
		},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "two acks", func() bool { _, acks, _ := rpc.snapshot(); return len(acks) == 2 })
	snaps, local, remote := ap.counts()
	if snaps != 1 || local != 1 || remote != 1 {
		t.Fatalf("applier counts snaps=%d local=%d remote=%d, want 1/1/1", snaps, local, remote)
	}
	if cur := c.ConfirmedCursor(); cur.Seq != 2 {
		t.Fatalf("remote delta must advance generation, cursor seq=%d want 2", cur.Seq)
	}
}

func TestApplyFailureNacksAndResyncsFromConfirmedCursor(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			deltaMsg("d1", upsertDelta(1, testRoute(1, 100, 0, "http", 7)), "sha-a"),
		},
		// Attempt 2 after resync: nothing more arrives in this script — the
		// point under test is the failed generation never confirming.
		{},
	}}
	ap := &scriptedApplier{failLocalSeq: map[uint64]int{1: 1}}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "nack sent and resync hello carries sha-a", func() bool {
		hellos, acks, _ := rpc.snapshot()
		if len(hellos) < 2 || hellos[1].GetCurrentSnapshotSha() != "sha-a" {
			return false
		}
		for _, a := range acks {
			if a.GetDeltaId() == "d1" && !a.GetOk() {
				return true
			}
		}
		return false
	})
	// Failed generation must not confirm.
	if cur := c.ConfirmedCursor(); cur.Seq != 0 || cur.SnapshotSHA != "sha-a" {
		t.Fatalf("cursor must stay at snapshot-only after failed delta, got %+v", cur)
	}
	if _, local, _ := ap.counts(); local != 1 {
		t.Fatalf("failed delta should have been attempted exactly once, got %d", local)
	}
}

func TestDuplicateDeltaReacksWithoutReapplying(t *testing.T) {
	d := upsertDelta(1, testRoute(1, 100, 0, "http", 7))
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			envSnapshotMsg("sha-a", 0),
			deltaMsg("d1", d, "sha-a"),
			deltaMsg("d1", d, "sha-a"), // redelivery (our ack was lost)
		},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "two acks for d1", func() bool {
		_, acks, _ := rpc.snapshot()
		n := 0
		for _, a := range acks {
			if a.GetDeltaId() == "d1" {
				n++
			}
		}
		return n == 2
	})
	if _, local, _ := ap.counts(); local != 1 {
		t.Fatalf("duplicate delta must not re-apply: local calls=%d, want 1", local)
	}
}

func TestAckLostBeforeStreamBreakIsResentOnReconnect(t *testing.T) {
	d := upsertDelta(1, testRoute(1, 100, 0, "http", 7))
	rpc := &fakeRPC{
		t: t,
		// send #1 = hello, send #2 = the ack that the network loses.
		failOnSend: map[int]bool{2: true},
		script: [][]*pb.ConfigMessage{
			{bareSnapshotMsg("sha-a"), deltaMsg("d1", d, "sha-a")},
			// Reconnect: server redelivers from its unacked position.
			{deltaMsg("d1", d, "sha-a")},
		},
	}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "reconnect resumes from sha-a and d1 acked", func() bool {
		hellos, acks, _ := rpc.snapshot()
		resumed := len(hellos) >= 2 && hellos[1].GetCurrentSnapshotSha() == "sha-a"
		okAcks := 0
		for _, a := range acks {
			if a.GetDeltaId() == "d1" && a.GetOk() {
				okAcks++
			}
		}
		return resumed && okAcks >= 1
	})
	if _, local, _ := ap.counts(); local != 1 {
		t.Fatalf("redelivery after ack loss must not re-apply: local calls=%d", local)
	}
}

func TestDeltaGapNacksAndResyncs(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			envSnapshotMsg("sha-a", 10),
			deltaMsg("d12", upsertDelta(12, testRoute(1, 100, 0, "http", 7)), "sha-a"),
		},
		{},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "gap nack + resync", func() bool {
		hellos, acks, _ := rpc.snapshot()
		if len(hellos) < 2 || hellos[1].GetCurrentSnapshotSha() != "sha-a" {
			return false
		}
		for _, a := range acks {
			if a.GetDeltaId() == "d12" && !a.GetOk() {
				return true
			}
		}
		return false
	})
	// Give the reconnect loop a moment in case the gapped delta leaked.
	time.Sleep(20 * time.Millisecond)
	snaps, local, _ := ap.counts()
	if local != 0 {
		t.Fatalf("gapped delta must not apply: local calls=%d", local)
	}
	if snaps != 1 {
		t.Fatalf("gapped delta stream must not re-baseline before reconnect: snaps=%d", snaps)
	}
}

func TestStaleSnapshotMustNotRegressState(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			envSnapshotMsg("sha-new", 10),
			envSnapshotMsg("sha-old", 3), // late/old snapshot
		},
		{},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "reconnect after refusing stale snapshot", func() bool {
		hellos, _, _ := rpc.snapshot()
		return len(hellos) >= 2
	})
	// Give the loop a moment to (wrongly) apply the stale snapshot.
	time.Sleep(20 * time.Millisecond)
	if snaps, _, _ := ap.counts(); snaps != 1 {
		t.Fatalf("stale snapshot must not be applied: snapshot calls=%d, want 1", snaps)
	}
	if cur := c.ConfirmedCursor(); cur.Seq != 10 {
		t.Fatalf("confirmed generation must stay at 10, got %d", cur.Seq)
	}
}

func TestMalformedDeltaNacksAndResyncs(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{bareSnapshotMsg("sha-a"), malformedDeltaMsg("dx")},
		{bareSnapshotMsg("sha-a")},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "malformed delta nacked + resync", func() bool {
		hellos, acks, _ := rpc.snapshot()
		if len(hellos) < 2 {
			return false
		}
		for _, a := range acks {
			if a.GetDeltaId() == "dx" && !a.GetOk() {
				return true
			}
		}
		return false
	})
	if _, local, _ := ap.counts(); local != 0 {
		t.Fatalf("malformed delta must not be applied")
	}
}

func TestParentSnapshotMismatchResyncs(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			deltaMsg("d1", upsertDelta(1, testRoute(1, 100, 0, "http", 7)), "sha-OTHER"),
		},
		{},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "parent mismatch nack", func() bool {
		_, acks, _ := rpc.snapshot()
		for _, a := range acks {
			if a.GetDeltaId() == "d1" && !a.GetOk() {
				return true
			}
		}
		return false
	})
	if _, local, _ := ap.counts(); local != 0 {
		t.Fatalf("delta with mismatched parent sha must not apply")
	}
}

func TestHeartbeatMessageAdvancesNothing(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			heartbeatMsg(),
			deltaMsg("d1", upsertDelta(1, testRoute(1, 100, 0, "http", 7)), "sha-a"),
		},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "delta after heartbeat applied", func() bool {
		_, acks, _ := rpc.snapshot()
		return len(acks) == 1 && acks[0].GetDeltaId() == "d1"
	})
	if cur := c.ConfirmedCursor(); cur.Seq != 1 {
		t.Fatalf("heartbeat must not disturb generation, seq=%d", cur.Seq)
	}
}

func TestLegacyNumericDeltaIDFallsBackToSequence(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{
			bareSnapshotMsg("sha-a"),
			deltaMsg("7", Delta{Kind: "upsert", Route: testRoute(1, 100, 0, "http", 7)}, "sha-a"),
			deltaMsg("8", Delta{Kind: "upsert", Route: testRoute(2, 100, 0, "http", 7)}, "sha-a"),
		},
	}}
	ap := &scriptedApplier{}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "two legacy acks", func() bool { _, acks, _ := rpc.snapshot(); return len(acks) == 2 })
	if cur := c.ConfirmedCursor(); cur.Seq != 8 {
		t.Fatalf("numeric delta_id should sequence cursor, got %d", cur.Seq)
	}
}

func TestCursorRecoversFromDiskAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/config-cursor.json"
	d := upsertDelta(1, testRoute(1, 100, 0, "http", 7))

	rpc1 := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{bareSnapshotMsg("sha-a"), deltaMsg("d1", d, "sha-a")},
	}}
	c1, cancel1 := startClient(t, rpc1, &scriptedApplier{}, path)
	waitFor(t, "first client confirms", func() bool {
		return c1.ConfirmedCursor().Seq == 1
	})
	cancel1()
	_ = c1.Close()

	// Simulate a process restart: a brand-new client over the same file.
	rpc2 := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{{}}}
	c2, cancel2 := startClient(t, rpc2, &scriptedApplier{}, path)
	defer cancel2()
	defer c2.Close()

	waitFor(t, "restarted client resumes from persisted sha", func() bool {
		hellos, _, _ := rpc2.snapshot()
		return len(hellos) > 0 && hellos[0].GetCurrentSnapshotSha() == "sha-a"
	})
	if cur := c2.ConfirmedCursor(); cur.Seq != 1 || cur.DeltaID != "d1" {
		t.Fatalf("recovered cursor = %+v, want seq=1 d1", cur)
	}
}

func TestSnapshotApplyFailureNacksAndKeepsConfirmed(t *testing.T) {
	rpc := &fakeRPC{t: t, script: [][]*pb.ConfigMessage{
		{envSnapshotMsg("sha-new", 11, testRoute(9, 100, 0, "http", 7))},
		{},
	}}
	ap := &scriptedApplier{failSnapshots: 1}
	c, cancel := startClient(t, rpc, ap, "")
	defer cancel()
	defer c.Close()

	waitFor(t, "snapshot failure nacked and stream reopened", func() bool {
		hellos, acks, _ := rpc.snapshot()
		if len(hellos) < 2 {
			return false
		}
		return len(acks) == 1 && !acks[0].GetOk()
	})
	if cur := c.ConfirmedCursor(); !cur.isZero() {
		t.Fatalf("failed snapshot must not confirm any generation, got %+v", cur)
	}
}
