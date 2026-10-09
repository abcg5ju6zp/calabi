// config_generation_test.go — the edge-side half of the config-generation
// protocol: a generation applies to router / port pool / policy AND the
// CONFIG_PUSH to online clients as one unit. A failed push fails the whole
// generation and leaves local state untouched; a snapshot replacement
// drives the port pool to the exact route set; remote routes stay
// locating-only and never move the pool.
package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// ---------- plumbing ----------

type fakeRegistrar struct {
	mu           sync.Mutex
	unregistered []string
}

func (f *fakeRegistrar) RegisterHTTP(string, *session.Session, string) error { return nil }
func (f *fakeRegistrar) RegisterSNI(string, *session.Session, string) error  { return nil }
func (f *fakeRegistrar) RegisterTCP(uint32, *session.Session, string) (io.Closer, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (f *fakeRegistrar) RegisterUDP(uint32, *session.Session, string) (io.Closer, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (f *fakeRegistrar) UnregisterByProxyID(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unregistered = append(f.unregistered, id)
}

func (f *fakeRegistrar) unregCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.unregistered)
}

// captureRWC records every frame the session writes; Read blocks forever
// (the tests never feed the session).
type captureRWC struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureRWC) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *captureRWC) Read([]byte) (int, error) { select {} }
func (c *captureRWC) Close() error             { return nil }

func (c *captureRWC) frames(t *testing.T) []proto.Frame {
	t.Helper()
	c.mu.Lock()
	data := c.buf.Bytes()
	c.mu.Unlock()
	r := bytes.NewReader(append([]byte(nil), data...))
	var out []proto.Frame
	for {
		f, err := proto.ReadFrame(r)
		if err != nil {
			return out
		}
		out = append(out, f)
	}
}

type brokenRWC struct{}

func (brokenRWC) Write([]byte) (int, error) { return 0, errors.New("control stream broken") }
func (brokenRWC) Read([]byte) (int, error)  { select {} }
func (brokenRWC) Close() error              { return nil }

func newTestSession(t *testing.T, deviceID int64, ctrl io.ReadWriteCloser) *session.Session {
	t.Helper()
	s := session.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, ctrl)
	s.DeviceID = deviceID
	return s
}

func genApplier(pool *router.PortPool, mgr *session.Manager, reg session.ProxyRegistrar, idx *tunnelIDIndex) *routeApplier {
	a := &routeApplier{
		edgeNodeID: testEdgeID,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		ports:      pool,
		manager:    mgr,
		registrar:  reg,
		index:      idx,
	}
	return a
}

func genRoute(id int, edge int64, kind string, port int32, clientID int64) configclient.Route {
	return configclient.Route{
		ID: id, Type: kind, Name: kind + "-tun", RemotePort: port,
		EdgeNodeID: edge, ClientID: clientID, Domain: "tun.example",
	}
}

// drainPorts allocates n ports from the pool and returns them as a set,
// so tests can assert membership regardless of allocation order.
func drainPorts(t *testing.T, pool *router.PortPool, n int) map[uint32]bool {
	t.Helper()
	out := map[uint32]bool{}
	for range n {
		p, ok := pool.Allocate()
		if !ok {
			t.Fatal("pool exhausted unexpectedly")
		}
		out[p] = true
	}
	return out
}

// ---------- tests ----------

// A snapshot replacement drives the pool to exactly the local route set:
// ports of rows present are reserved, ports of rows absent are freed.
func TestSnapshotReplacementDrivesPortPool(t *testing.T) {
	pool := router.NewPortPool(20000, 20099)
	a := genApplier(pool, nil, nil, nil)

	if err := a.OnSnapshot([]configclient.Route{
		genRoute(1, testEdgeID, "udp", 20000, 0),
		genRoute(2, testEdgeID, "tcp", 20001, 0),
		genRoute(3, testEdgeID+1, "tcp", 20005, 0), // remote: pool-untouched
	}); err != nil {
		t.Fatalf("OnSnapshot: %v", err)
	}
	// 20000/20001 skipped (reserved), the next four free numbers must
	// include the remote route's 20005 — proving remote rows don't reserve.
	got := drainPorts(t, pool, 4)
	if got[20000] || got[20001] {
		t.Fatalf("local snapshot ports must be reserved, allocatable=%v", got)
	}
	if !got[20005] {
		t.Fatalf("remote route's port must stay allocatable, got=%v", got)
	}

	// Replacement without the local rows frees both numbers: they are the
	// only entries on the free list now.
	if err := a.OnSnapshot(nil); err != nil {
		t.Fatalf("OnSnapshot empty: %v", err)
	}
	freed := drainPorts(t, pool, 2)
	if !freed[20000] || !freed[20001] {
		t.Fatalf("freed ports = %v, want 20000 and 20001 back", freed)
	}
}

// An upsert delta reserves the row's port; a remote upsert never does.
func TestUpsertDeltaReservesLocalPortOnly(t *testing.T) {
	pool := router.NewPortPool(20000, 20099)
	a := genApplier(pool, nil, nil, nil)

	if err := a.OnLocalDelta(configclient.Delta{
		Kind: "upsert", Route: genRoute(1, testEdgeID, "tcp", 20003, 0),
	}); err != nil {
		t.Fatalf("OnLocalDelta: %v", err)
	}

	a.OnRemoteDelta(configclient.Delta{
		Kind: "upsert", Route: genRoute(2, testEdgeID+1, "tcp", 20007, 0),
	})
	// Eight allocations over 20000..20008: 20003 must be missing (local
	// reserve), the remote route's 20007 must be present.
	got := drainPorts(t, pool, 8)
	if got[20003] {
		t.Fatalf("local upsert must reserve 20003, allocatable=%v", got)
	}
	if !got[20007] {
		t.Fatalf("remote upsert must leave 20007 allocatable, got=%v", got)
	}
}

// A local delete frees the port AND tears the router entry down.
func TestDeleteDeltaFreesPortAndUnregisters(t *testing.T) {
	pool := poolHolding20000(t)
	reg := &fakeRegistrar{}
	idx := &tunnelIDIndex{}
	idx.set(28, "proxy-28")
	a := genApplier(pool, nil, reg, idx)

	if err := a.OnLocalDelta(configclient.Delta{
		Kind: "delete", Route: genRoute(28, testEdgeID, "udp", 20000, 0),
	}); err != nil {
		t.Fatalf("OnLocalDelta delete: %v", err)
	}
	if reg.unregCount() != 1 {
		t.Fatalf("registrar unregistrations = %d, want 1", reg.unregCount())
	}
	if _, ok := idx.get(28); ok {
		t.Fatal("index entry must be removed after delete")
	}
	got, ok := pool.Allocate()
	if !ok || got != 20000 {
		t.Fatalf("port not freed after delete: got=%d ok=%v", got, ok)
	}
}

// The CONFIG_PUSH is part of the generation: when the owning client is
// online and its control stream is broken, the generation fails and NO
// local effect (here: port reservation) may take effect.
func TestConfigPushFailureFailsGenerationWithoutLocalMutation(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	mgr.Register(newTestSession(t, 77, brokenRWC{}))
	pool := router.NewPortPool(20000, 20099)
	a := genApplier(pool, mgr, nil, nil)

	err := a.OnLocalDelta(configclient.Delta{
		Kind: "upsert", Route: genRoute(1, testEdgeID, "tcp", 20004, 77),
	})
	if err == nil {
		t.Fatal("broken online client must fail the delta generation")
	}
	// Nothing reserved: the whole 100-port range stays allocatable.
	if got := drainPorts(t, pool, 100); !got[20004] {
		t.Fatalf("failed delta generation must leave the pool untouched")
	}

	// Fresh pool for the snapshot attempt (the first drain consumed it).
	pool2 := router.NewPortPool(20000, 20099)
	a.ports = pool2
	if err := a.OnSnapshot([]configclient.Route{genRoute(1, testEdgeID, "tcp", 20004, 77)}); err == nil {
		t.Fatal("broken online client must fail the snapshot generation")
	}
	if got := drainPorts(t, pool2, 100); !got[20004] {
		t.Fatalf("failed snapshot must leave the pool untouched")
	}
}

// An offline owning client (no live session) does not hold the generation
// hostage: there is simply no push to send, and local state applies.
func TestOfflineClientDoesNotBlockGeneration(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	pool := router.NewPortPool(20000, 20099)
	a := genApplier(pool, mgr, nil, nil)

	if err := a.OnLocalDelta(configclient.Delta{
		Kind: "upsert", Route: genRoute(1, testEdgeID, "tcp", 20006, 88),
	}); err != nil {
		t.Fatalf("offline client must not fail the generation: %v", err)
	}
	got := drainPorts(t, pool, 9) // 20000..20008 with 20006 held
	if got[20006] {
		t.Fatalf("offline client's row port must still be reserved, got=%v", got)
	}
}

// A snapshot replacement sends an authoritative FullSync CONFIG_PUSH to
// each ONLINE client with its own tunnels (and none to offline clients).
func TestSnapshotFullSyncPushedToOnlineClients(t *testing.T) {
	rwc := &captureRWC{}
	mgr := session.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	mgr.Register(newTestSession(t, 77, rwc)) // client 77 online, 88 offline

	a := genApplier(router.NewPortPool(20000, 20099), mgr, nil, nil)
	routes := []configclient.Route{
		genRoute(1, testEdgeID, "http", 0, 77),
		genRoute(2, testEdgeID+1, "tcp", 20002, 77), // client 77's tunnel on another edge
		genRoute(3, testEdgeID, "http", 0, 88),      // offline client: skipped
	}
	if err := a.OnSnapshot(routes); err != nil {
		t.Fatalf("OnSnapshot: %v", err)
	}

	var pushes []*proto.ConfigPush
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pushes = nil
		for _, f := range rwc.frames(t) {
			if f.Type != proto.FrameConfigPush {
				continue
			}
			var p proto.ConfigPush
			if err := proto.Unmarshal(f.Payload, &p); err != nil {
				t.Fatal(err)
			}
			pushes = append(pushes, &p)
		}
		if len(pushes) == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(pushes) != 1 {
		t.Fatalf("want exactly one FullSync for the online client, got %d", len(pushes))
	}
	if !pushes[0].FullSync {
		t.Fatal("snapshot push must be authoritative FullSync")
	}
	if len(pushes[0].UpsertProxies) != 2 {
		t.Fatalf("FullSync should list client 77's two tunnels (any edge), got %d",
			len(pushes[0].UpsertProxies))
	}
}

// Remote deltas keep their original best-effort behavior: a broken client
// push is swallowed and the pool never moves.
func TestRemoteDeltaBestEffortNeverFails(t *testing.T) {
	mgr := session.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	mgr.Register(newTestSession(t, 77, brokenRWC{}))
	pool := router.NewPortPool(20000, 20099)
	a := genApplier(pool, mgr, nil, nil)

	a.OnRemoteDelta(configclient.Delta{
		Kind: "upsert", Route: genRoute(1, testEdgeID+1, "tcp", 20008, 77),
	})
	got := drainPorts(t, pool, 9) // 20000..20008, nothing held
	if !got[20008] {
		t.Fatalf("remote route must leave its port allocatable, got=%v", got)
	}
}
