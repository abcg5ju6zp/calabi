package certclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabinet/calabi/pkg/certevents"
	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// This package had no tests at all until the org-scope bug, which is part of
// why the bug lived so long. The generation rewrite added the partial-
// fetch recovery, ordering, delete-fencing and snapshot cases that follow.

// fakeRPC serves a controllable catalog.
type fakeRPC struct {
	catalog  []*pb.CertMeta
	material map[int64]*pb.GetCertResponse
	lastList *pb.ListCertsRequest
	listCall int
	getCalls map[int64]int
	failGet  map[int64]error
	listErr  error
}

func (f *fakeRPC) ListCerts(_ context.Context, in *pb.ListCertsRequest, _ ...grpc.CallOption) (*pb.ListCertsResponse, error) {
	f.listCall++
	f.lastList = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &pb.ListCertsResponse{Items: f.catalog}, nil
}

func (f *fakeRPC) GetCert(_ context.Context, in *pb.GetCertRequest, _ ...grpc.CallOption) (*pb.GetCertResponse, error) {
	if f.getCalls == nil {
		f.getCalls = map[int64]int{}
	}
	f.getCalls[in.GetId()]++
	if err := f.failGet[in.GetId()]; err != nil {
		return nil, err
	}
	if got, ok := f.material[in.GetId()]; ok {
		return got, nil
	}
	return &pb.GetCertResponse{}, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newClient builds a Client without the poller, so a test drives refresh()
// itself and nothing races with it.
func newClient(t *testing.T, rpc RPC, orgID int64) *Client {
	t.Helper()
	c := &Client{
		rpc:    rpc,
		logger: quietLogger(),
		orgID:  orgID,
		stopCh: make(chan struct{}),
		kick:   make(chan struct{}, 1),
	}
	c.pool.Store(emptyGeneration())
	return c
}

func newClientWithStore(t *testing.T, rpc RPC, orgID int64, dir string) *Client {
	t.Helper()
	c := newClient(t, rpc, orgID)
	c.store = newSnapshotStore(dir, c.logger)
	return c
}

func TestRefreshBuildsThePoolFromTheListing(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "a.example.com")
	addCert(t, f, 2, 42, "b.example.com")

	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for _, sni := range []string{"a.example.com", "b.example.com"} {
		if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err != nil {
			t.Errorf("%s not in the pool: %v", sni, err)
		}
	}
	// Two different orgs. Before bff-edge could ask for all of them, a platform
	// edge's listing carried one org and the other cert was simply not there.
	if c.PoolSize() != 2 {
		t.Errorf("pool size = %d, want 2", c.PoolSize())
	}
}

// TestAReconcileReplacesThePool is the mechanism behind the org-scope bug,
// pinned as behaviour rather than left as a surprise.
//
// The 5-minute reconcile is not a merge of strangers: a cert the listing
// OMITS (and that cannot prove it is newer than the listing, as a fresh
// push can) is evicted, so the SCOPE of the listing decides which tenants
// a node serves — not just how fresh its pool is.
func TestAReconcileReplacesThePool(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "stays.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// A cert for a DIFFERENT org arrives by push, exactly as onUpsert would
	// install it.
	pushed := addCert(t, f, 2, 42, "pushed.example.com")
	f.catalog = f.catalog[:1] // ...but the listing does not cover org 42
	installPushed(t, c, 2, 42, "pushed.example.com", pushed)

	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "pushed.example.com"}); err != nil {
		t.Fatalf("the pushed cert should be serving straight away: %v", err)
	}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "pushed.example.com"}); err == nil {
		t.Fatal("a reconcile whose listing omits a cert older than the listing must drop it — if this ever merges instead, " +
			"the listing's scope stops being load-bearing and this test should say so")
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "stays.example.com"}); err != nil {
		t.Errorf("the listed cert should survive: %v", err)
	}
}

// The wildcard fallback, which decides whether a platform node can serve
// u<N>.<region>.calabi.online out of one *.region cert.
func TestWildcardFallback(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 1, "*.sgp.calabi.online")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "u000001.sgp.calabi.online"}); err != nil {
		t.Errorf("wildcard did not cover a one-label subdomain: %v", err)
	}
	// One label only — a wildcard cert is not valid two levels down, and
	// serving it there would be worse than failing the handshake.
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.b.sgp.calabi.online"}); err == nil {
		t.Error("wildcard matched two levels down")
	}
}

// A SNI the pool does not cover fails the handshake rather than fetching.
func TestUnknownSNIDoesNotFetch(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := f.listCall
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "nobody.example.com"}); err != ErrNoCertForSNI {
		t.Errorf("err = %v, want ErrNoCertForSNI", err)
	}
	if f.listCall != before {
		t.Error("a miss triggered a fetch; this client has no on-demand path")
	}
}

// ---------- the rotation outage this rewrite exists to stop ----------

// While a new catalog is only PARTIALLY fetchable, the old generation keeps
// serving; the complete candidate goes live only once the missing key lands.
func TestPartialFetchKeepsOldGenerationAndRetries(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "old.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	oldCert, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "old.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// A rotation adds a second cert but its private key endpoint is failing.
	addCert(t, f, 2, 7, "new.example.com")
	f.failGet = map[int64]error{2: status.Error(codes.Unavailable, "key not ready")}

	if err := c.refresh(context.Background()); !errors.Is(err, errIncompleteGeneration) {
		t.Fatalf("refresh err = %v, want errIncompleteGeneration", err)
	}
	// The new cert must NOT be half-installed...
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "new.example.com"}); err == nil {
		t.Fatal("new cert served although its key never came down")
	}
	// ...and the old cert must STILL be serving.
	cur, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "old.example.com"})
	if err != nil {
		t.Fatalf("old cert evicted by an incomplete generation: %v", err)
	}
	if cur != oldCert {
		t.Fatal("the old cert pointer changed despite the failed candidate")
	}
	if c.pending == nil {
		t.Fatal("expected an armed pending candidate for the missing cert")
	}
	if _, missing := c.pending.missing[2]; !missing {
		t.Fatalf("missing set = %v, want id 2", c.pending.missing)
	}

	// Key becomes available: the INDIVIDUAL retry completes the generation;
	// already-fetched cert 1 is not refetched.
	delete(f.failGet, 2)
	id1Fetches := f.getCalls[1]
	if err := c.retryPending(context.Background()); err != nil {
		t.Fatalf("retryPending: %v", err)
	}
	if c.pending != nil {
		t.Fatal("pending candidate should be committed and cleared")
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "new.example.com"}); err != nil {
		t.Errorf("new cert not serving after missing-key retry: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "old.example.com"}); err != nil {
		t.Errorf("old cert lost on candidate completion: %v", err)
	}
	if f.getCalls[1] != id1Fetches {
		t.Errorf("cert 1 refetched during targeted retry: %d -> %d", id1Fetches, f.getCalls[1])
	}
}

// A missing cert that returns NotFound on retry means the listing moved on;
// the stale pending candidate is dropped in favour of a fresh reconcile.
func TestMissingCertNotFoundReconcilesFresh(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "a.example.com")
	addCert(t, f, 2, 7, "gone.example.com")
	f.failGet = map[int64]error{2: status.Error(codes.Unavailable, "later")}
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); !errors.Is(err, errIncompleteGeneration) {
		t.Fatalf("refresh: %v", err)
	}

	// Cert 2 is deleted before the retry: both the listing and the material
	// lose it, and GetCert now says NotFound.
	f.catalog = f.catalog[:1]
	delete(f.material, 2)
	f.failGet = map[int64]error{2: status.Error(codes.NotFound, "deleted")}

	if err := c.retryPending(context.Background()); err != nil {
		t.Fatalf("retryPending: %v", err)
	}
	if c.pending != nil {
		t.Fatal("pending candidate must be discarded")
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "gone.example.com"}); err == nil {
		t.Fatal("vanished cert still serving after NotFound resync")
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"}); err != nil {
		t.Errorf("surviving cert lost: %v", err)
	}
}

// A stale LISTING cannot downgrade a fresher push, nor evict a push newer
// than the listing's as-of watermark.
func TestStaleListingDoesNotDowngradePushedCert(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t1 := addCertV(t, f, 1, 7, 100, "svc.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Push renews the cert at a newer server watermark (addCertV replaces
	// both the catalog row and the GetCert material for id 1).
	t2 := addCertV(t, f, 1, 7, 200, "svc.example.com")
	c.onUpsert(upsertMsg(1, 7, 200, fingerprint(1, 200), "svc.example.com"))
	assertServingLeaf(t, c, "svc.example.com", t2.leaf)

	// A stale replica answers ListCerts + GetCert with the v100 material.
	staleMeta := certMeta(1, 7, 100, t1.fp, []string{"svc.example.com"})
	staleResp := respFor(staleMeta, t1)
	f.catalog = []*pb.CertMeta{staleMeta}
	f.material[1] = staleResp

	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("stale refresh: %v", err)
	}
	assertServingLeaf(t, c, "svc.example.com", t2.leaf) // still the pushed v200

	// A stale listing that merely OMITS a newer-than-as-of push entry
	// retains it.
	t3 := addCertV(t, f, 3, 7, 300, "extra.example.com")
	c.onUpsert(upsertMsg(3, 7, 300, fingerprint(3, 300), "extra.example.com"))
	f.catalog = []*pb.CertMeta{staleMeta} // asOf = 100; knows nothing of id3 v300
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("stale refresh 2: %v", err)
	}
	assertServingLeaf(t, c, "extra.example.com", t3.leaf)
	assertServingLeaf(t, c, "svc.example.com", t2.leaf)
}

// A FRESH listing (as-of newer than the push) authoritatively evicts the
// cert the server no longer lists.
func TestFreshListingEvictsAfterDelete(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, f, 1, 7, 100, "svc.example.com")
	t9 := addCertV(t, f, 9, 7, 200, "temp.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertServingLeaf(t, c, "temp.example.com", t9.leaf)

	// Fresh listing: id1 renewed at v400 (as-of 400); id9 is gone (deleted
	// at 300). addCertV replaces id1's catalog row; [:1] drops id9.
	f.catalog = f.catalog[:1]
	t400 := addCertV(t, f, 1, 7, 400, "svc.example.com")
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "temp.example.com"}); err == nil {
		t.Fatal("fresh listing must evict a deleted cert")
	}
	assertServingLeaf(t, c, "svc.example.com", t400.leaf)
}

// An EMPTY but successful listing is authoritative (the org has no certs /
// scope shrank to nothing): it evicts, since it carries no as-of watermark
// a stale-push defence could compare against. This is the historical
// behaviour and must not regress into retaining entries forever.
func TestEmptyListingIsAuthoritative(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, f, 1, 7, 100, "svc.example.com")
	addCertV(t, f, 9, 7, 300, "pushed.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.catalog = nil
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.PoolSize() != 0 {
		t.Fatalf("empty listing did not evict; pool size = %d", c.PoolSize())
	}
	if len(c.pool.Load().entries) != 0 {
		t.Fatalf("entries survived an authoritative empty listing: %d", len(c.pool.Load().entries))
	}
}

// ---------- delete semantics: confirmed, fenced, in-flight safe ----------

func TestDeleteConfirmedFencedAndInFlightSafe(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t1 := addCertV(t, f, 1, 7, 100, "svc.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	inFlight, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// Explicit delete at watermark 200: new handshakes stop using it once
	// the generation commits.
	c.onDelete(deleteMsg(1, 7, 200))
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"}); err == nil {
		t.Fatal("deleted cert still offered for new handshakes")
	}
	// A handshake that already fetched its pointer finishes untouched.
	if !bytes.Equal(inFlight.Certificate[0], t1.leaf) {
		t.Fatal("in-flight handshake cert changed under it")
	}

	// Duplicate/redelivered deletes are no-ops (seq unchanged).
	seqAfter := c.pool.Load().seq
	c.onDelete(deleteMsg(1, 7, 200))
	c.onDelete(deleteMsg(1, 7, 150))
	if got := c.pool.Load().seq; got != seqAfter {
		t.Fatalf("redelivered delete produced a new generation: %d != %d", got, seqAfter)
	}

	// A stale listing still showing the cert at v100 must NOT resurrect it.
	stale := certMeta(1, 7, 100, t1.fp, []string{"svc.example.com"})
	f.catalog = []*pb.CertMeta{stale}
	f.material[1] = respFor(stale, t1)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("stale refresh after delete: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"}); err == nil {
		t.Fatal("stale listing resurrected a deleted cert")
	}
	g := c.pool.Load()
	if tv, ok := g.tombstones[1]; !ok || tv != 200 {
		t.Fatalf("tombstone lost: %v", g.tombstones)
	}
}

// Redelivered upserts are idempotent: fingerprint already serving → no
// refetch at all; an upsert older than the serving version is ignored.
func TestDuplicateAndStaleUpsertsAreNoOps(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t100 := addCertV(t, f, 1, 7, 100, "svc.example.com")
	c := newClient(t, f, 0)
	c.onUpsert(upsertMsg(1, 7, 100, t100.fp, "svc.example.com"))
	if f.getCalls[1] != 1 {
		t.Fatalf("GetCert calls = %d, want 1", f.getCalls[1])
	}
	// NATS/bff redelivery (event applied, ack lost).
	c.onUpsert(upsertMsg(1, 7, 100, t100.fp, "svc.example.com"))
	if f.getCalls[1] != 1 {
		t.Fatalf("redelivered upsert refetched: %d calls", f.getCalls[1])
	}

	// An older upsert for the same id must not downgrade.
	t50 := addCertV(t, f, 1, 7, 50, "svc.example.com")
	c.onUpsert(upsertMsg(1, 7, 50, t50.fp, "svc.example.com"))
	cur, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "svc.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cur.Certificate[0], t50.leaf) {
		t.Fatal("a v50 upsert downgraded the serving v100 cert")
	}
}

// A push whose GetCert fails changes nothing and requests a reconcile.
func TestPushFetchFailureKeepsServing(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "up.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.failGet = map[int64]error{2: status.Error(codes.Unavailable, "boom")}
	c.onUpsert(upsertMsg(2, 7, 100, fingerprint(2, 100), "down.example.com"))
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "up.example.com"}); err != nil {
		t.Fatalf("healthy cert disturbed by a failed push: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "down.example.com"}); err == nil {
		t.Fatal("failed push must not install anything")
	}
	select {
	case <-c.kick:
	default:
		t.Fatal("failed push did not request a reconcile")
	}
}

// Same digest → reconnect/poll costs one ListCerts and ZERO GetCerts.
func TestSameServerGenerationSkipsRefetch(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, f, 1, 7, 100, "a.example.com")
	addCertV(t, f, 2, 7, 100, "b.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	listBefore := f.listCall
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.listCall != listBefore+1 {
		t.Fatalf("ListCerts calls = %d, want one comparison", f.listCall)
	}
	if f.getCalls[1] != 1 || f.getCalls[2] != 1 {
		t.Fatalf("unchanged generation refetched keys: %v", f.getCalls)
	}
}

// ---------- encrypted snapshot recovery ----------

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t1 := addCertV(t, f, 1, 7, 100, "persist.example.com")
	c := newClientWithStore(t, f, 0, dir)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	g, err := newSnapshotStore(dir, quietLogger()).load()
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if g == nil || len(g.entries) != 1 {
		t.Fatalf("snapshot entries = %v", g)
	}
	assertServingLeafOn(t, g, "persist.example.com", t1.leaf)
}

// Startup with the control plane unreachable serves the last confirmed
// snapshot; with no snapshot it serves an empty pool.
func TestStartupOfflineServesLastSnapshot(t *testing.T) {
	dir := t.TempDir()
	good := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, good, 1, 7, 100, "boot.example.com")
	c1, err := StartWithClient(context.Background(), quietLogger(), good, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}

	offline := &fakeRPC{
		material: map[int64]*pb.GetCertResponse{},
		listErr:  status.Error(codes.Unavailable, "control plane down"),
	}
	c2, err := StartWithClient(context.Background(), quietLogger(), offline, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.GetCertificate(&tls.ClientHelloInfo{ServerName: "boot.example.com"}); err != nil {
		t.Fatalf("last confirmed generation not served offline: %v", err)
	}

	// No state dir, control plane down: empty pool, no crash.
	cold, err := StartWithClient(context.Background(), quietLogger(), offline, Options{
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if cold.PoolSize() != 0 {
		t.Fatalf("cold offline pool size = %d, want 0", cold.PoolSize())
	}
}

// BYOI listing denial keeps its historical behaviour: empty pool even if a
// snapshot file happens to be present.
func TestStartupPermissionDeniedStaysEmpty(t *testing.T) {
	dir := t.TempDir()
	good := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, good, 1, 7, 100, "byoi.example.com")
	c1, err := StartWithClient(context.Background(), quietLogger(), good, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()

	denied := &fakeRPC{
		material: map[int64]*pb.GetCertResponse{},
		listErr:  status.Error(codes.PermissionDenied, "listing not allowed for BYOI edge"),
	}
	c2, err := StartWithClient(context.Background(), quietLogger(), denied, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.PoolSize() != 0 {
		t.Fatalf("BYOI pool size after denial = %d, want 0", c2.PoolSize())
	}
}

// A failed snapshot PUBLISH leaves the previous confirmed file intact.
func TestSnapshotPublishFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t1 := addCertV(t, f, 1, 7, 100, "keep.example.com")
	c := newClientWithStore(t, f, 0, dir)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A store whose "dir" is a regular FILE cannot temp-write.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := newSnapshotStore(blocker, quietLogger())
	if err := bad.save(c.pool.Load()); err == nil {
		t.Fatal("expected publish failure")
	}
	// The good store's file is unchanged and still loads.
	reloaded, err := newSnapshotStore(dir, quietLogger()).load()
	if err != nil {
		t.Fatalf("old snapshot damaged: %v", err)
	}
	assertServingLeafOn(t, reloaded, "keep.example.com", t1.leaf)
}

// Tampered ciphertext → cold start, never a half generation.
func TestSnapshotCorruptionRefused(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCertV(t, f, 1, 7, 100, "x.example.com")
	c := newClientWithStore(t, f, 0, dir)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, snapshotFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the sealed payload (after magic+nonce).
	raw[len(snapshotMagic)+snapshotNonce+3] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := newSnapshotStore(dir, quietLogger()).load(); err == nil {
		t.Fatalf("tampered snapshot accepted: %v", g)
	}
}

// A generation reloaded from snapshot replays events idempotently: a
// redelivered upsert after boot costs no GetCert.
func TestRedeliveredEventAfterRestart(t *testing.T) {
	dir := t.TempDir()
	good := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	t1 := addCertV(t, good, 1, 7, 100, "replay.example.com")
	c1, err := StartWithClient(context.Background(), quietLogger(), good, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()

	offline := &fakeRPC{
		material: good.material,
		catalog:  good.catalog,
		listErr:  status.Error(codes.Unavailable, "down"),
	}
	c2, err := StartWithClient(context.Background(), quietLogger(), offline, Options{
		StateDir:        dir,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.onUpsert(upsertMsg(1, 7, 100, t1.fp, "replay.example.com"))
	if offline.getCalls[1] != 0 {
		t.Fatal("redelivered upsert after restart refetched")
	}
}

// RequestResync drives the poller: a catalog change with no event bus is
// picked up when the signal fires, not only at the long poll interval.
func TestRequestResyncDrivesImmediateReconcile(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "one.example.com")
	c, err := StartWithClient(context.Background(), quietLogger(), f, Options{
		RefreshInterval: time.Hour, // poll alone would never fire in the test
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	addCert(t, f, 2, 7, "two.example.com")
	c.RequestResync()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.PoolSize() == 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("resync signal never reconciled the new cert; pool size = %d", c.PoolSize())
}

// ---------- helpers ----------

// fixtureCert is the generated material one test cert: identity plus PEMs.
type fixtureCert struct {
	fp        string
	leaf      []byte
	fullchain []byte
	keyPEM    []byte
}

// addCert appends an UNVERSIONED cert (as an old publisher would emit) and
// returns its GetCert payload.
func addCert(t *testing.T, f *fakeRPC, id, org int64, sans ...string) *pb.GetCertResponse {
	t.Helper()
	fullchain, key := genPair(t, sans)
	got := &pb.GetCertResponse{FullchainPem: fullchain, PrivateKeyPem: key}
	f.material[id] = got
	f.catalog = append(f.catalog, &pb.CertMeta{
		Meta:    &pb.ResourceMeta{Id: id},
		OrgId:   org,
		Sans:    sans,
		Subject: sans[0],
	})
	return got
}

// addCertV installs (or renews, replacing any row with the same id) a cert
// at a server watermark with a deterministic fingerprint.
func addCertV(t *testing.T, f *fakeRPC, id, org, version int64, sans ...string) fixtureCert {
	t.Helper()
	fullchain, keyPEM := genPair(t, sans)
	fp := fingerprint(id, version)
	meta := certMeta(id, org, version, fp, sans)
	f.material[id] = &pb.GetCertResponse{
		Cert:          meta,
		FullchainPem:  fullchain,
		PrivateKeyPem: keyPEM,
	}
	var out []*pb.CertMeta
	for _, m := range f.catalog {
		if m.GetMeta().GetId() != id {
			out = append(out, m)
		}
	}
	f.catalog = append(out, meta)
	return fixtureCert{
		fp:        fp,
		leaf:      leafDER(t, fullchain),
		fullchain: fullchain,
		keyPEM:    keyPEM,
	}
}

func fingerprint(id, version int64) string {
	return fmt.Sprintf("fp-%d-%d", id, version)
}

func certMeta(id, org, version int64, fp string, sans []string) *pb.CertMeta {
	m := &pb.CertMeta{
		Meta:        &pb.ResourceMeta{Id: id},
		OrgId:       org,
		Sans:        sans,
		Subject:     sans[0],
		Fingerprint: fp,
	}
	if version != 0 {
		m.Meta.UpdatedAt = timestamppb.New(time.Unix(0, version))
	}
	return m
}

// respFor builds the GetCert payload for a (possibly stale) listing meta
// using the PEM pair the fixture generated.
func respFor(meta *pb.CertMeta, tc fixtureCert) *pb.GetCertResponse {
	return &pb.GetCertResponse{
		Cert:          meta,
		FullchainPem:  tc.fullchain,
		PrivateKeyPem: tc.keyPEM,
	}
}

// installPushed puts a cert into the pool the way onUpsert does, without a
// bus or an event.
func installPushed(t *testing.T, c *Client, id, org int64, sni string, got *pb.GetCertResponse) {
	t.Helper()
	tc, err := parsePair(got.GetFullchainPem(), got.GetPrivateKeyPem())
	if err != nil {
		t.Fatalf("parse pushed pair: %v", err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	cur := c.pool.Load()
	entries := cloneEntries(cur.entries)
	entries[id] = &certEntry{
		id:            id,
		orgID:         org,
		cert:          tc,
		sans:          []string{sni},
		subject:       sni,
		fullchainPEM:  append([]byte(nil), got.GetFullchainPem()...),
		privateKeyPEM: append([]byte(nil), got.GetPrivateKeyPem()...),
	}
	c.commitLocked(projectGeneration(c.nextSeqLocked(), entries, cloneTombstones(cur.tombstones)))
}

func upsertMsg(id, org, version int64, fp string, sans ...string) *eventbus.Msg {
	body, _ := json.Marshal(certevents.CertEvent{
		CertID:      id,
		OrgID:       org,
		SANs:        sans,
		Subject:     sans[0],
		Fingerprint: fp,
		Version:     version,
	})
	return &eventbus.Msg{Subject: certevents.UpsertSubject(org), Data: body}
}

func deleteMsg(id, org, version int64) *eventbus.Msg {
	body, _ := json.Marshal(certevents.CertEvent{CertID: id, OrgID: org, Version: version})
	return &eventbus.Msg{Subject: certevents.DeleteSubject(org), Data: body}
}

func assertServingLeaf(t *testing.T, c *Client, sni string, leaf []byte) {
	t.Helper()
	got, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("%s not served: %v", sni, err)
	}
	if !bytes.Equal(got.Certificate[0], leaf) {
		t.Fatalf("%s served the wrong certificate", sni)
	}
}

func assertServingLeafOn(t *testing.T, g *generation, sni string, leaf []byte) {
	t.Helper()
	cert, ok := g.bySNI[sni]
	if !ok {
		t.Fatalf("%s missing from generation", sni)
	}
	if !bytes.Equal(cert.Certificate[0], leaf) {
		t.Fatalf("%s wrong leaf", sni)
	}
}

func leafDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem decode")
	}
	return block.Bytes
}

func genPair(t *testing.T, sans []string) (fullchain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
