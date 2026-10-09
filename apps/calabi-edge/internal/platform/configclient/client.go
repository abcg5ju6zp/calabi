// Package configclient subscribes to config-svc's Subscribe stream so
// the edge gets live snapshot + delta notifications when tunnels are
// created / updated / deleted elsewhere in the cluster.
//
// plumbs hot-apply: deltas affecting THIS edge's own tunnels
// (route.edge_node_id == self) feed an Applier that mutates the local
// router; deltas for remote edges go into a "known elsewhere" log so
// HTTP/TCP visitors hitting the wrong edge can be told where to go.
//
// # Configuration generations, confirmation and recovery
//
// Every snapshot and delta sits at one position in a total order — the
// configuration generation (snapshot sha + a continuous delta sequence).
// The edge ACKs a generation only AFTER the Applier reports that the
// local router, port occupancy, policy and the CONFIG_PUSH to every
// online client have ALL taken effect. Until then the confirmed cursor
// does not move.
//
//	delta JSON parse error, or any apply step failing
//	  -> Ack(ok=false) naming the failure and the confirmed position,
//	     then the stream is torn down and reopened; the edge either
//	     resumes deltas after its persisted cursor or, when the server
//	     cannot resume, re-baselines from a full snapshot replacement.
//
//	ack sent but lost (stream broke first)
//	  -> the server redelivers the same delta; it is a duplicate of the
//	     confirmed generation, so nothing is re-applied and the ack is
//	     simply re-sent.
//
//	partial local apply failing
//	  -> the Applier compensates local state back to the previous
//	     (confirmed) generation; the edge nacks and resyncs as above.
//
//	process restart
//	  -> the confirmed cursor is loaded from the CursorStore (state.dir),
//	     sent in HelloEdge.current_snapshot_sha, and the edge continues
//	     from that generation.
//
// An older snapshot or a delta that is not the next expected one can
// never move state backwards: it is refused and triggers the same
// resume/replace recovery.
package configclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// Route is the per-tunnel projection we get from config-svc deltas.
// Mirrors apps/tunnel-svc/internal/events.Tunnel.
type Route struct {
	ID            int    `json:"id"`
	OrgID         int64  `json:"org_id"`
	WorkspaceID   int64  `json:"workspace_id"`
	ClientID      int64  `json:"client_id,omitempty"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	LocalAddr     string `json:"local_addr,omitempty"`
	Domain        string `json:"domain"`
	Subdomain     string `json:"subdomain,omitempty"`
	RemotePort    int32  `json:"remote_port"`
	EdgeNodeID    int64  `json:"edge_node_id"`
	EdgeNodeLabel string `json:"edge_node_label"`
	Status        string `json:"status"`
	// ConfigJSON is the tunnel's server-authoritative config blob (security
	// policy: IP allowlist, …). config-svc already broadcasts it (tunnel-svc's
	// events.Tunnel carries it); the edge decodes it here so a console/SPA
	// policy edit can hot-update the live proxy via OnLocalDelta WITHOUT a
	// reconnect. Empty = no policy. See apps/calabi-edge/internal/policy.
	ConfigJSON string `json:"config_json"`
}

// Delta is what config-svc broadcasts. Mirrors apps/config-svc/internal/hub.Delta.
type Delta struct {
	ID    uint64 `json:"id"`
	Kind  string `json:"kind"` // "upsert" | "delete"
	Route Route  `json:"route"`
}

// snapshotEnvelope is the generation-carrying wrapper a config-svc sends
// for a full snapshot. A server older than the envelope still streams a
// bare JSON array of Route; decodeSnapshotBody accepts both shapes, so
// the edge keeps working against it (generation stays 0 and the sha is
// the only ordering token).
type snapshotEnvelope struct {
	Generation uint64  `json:"generation"`
	DeltaID    string  `json:"delta_id,omitempty"`
	Routes     []Route `json:"routes"`
}

// Applier receives parsed routes from the stream.
//
// OnSnapshot hands over a full route set that REPLACES the current view;
// it is used on first connection and whenever the server cannot resume
// from the edge's cursor.
//
// OnLocalDelta is called when route.edge_node_id == self; the edge MUST
// reflect the change in its local router / port pool / policy and push it
// to the owning online client. A non-nil error means the generation was
// NOT applied: the Applier MUST have already compensated any partial
// local effect back to the previous (confirmed) state before returning.
// configclient answers the generation with ok=false and resyncs.
//
// OnRemoteDelta is called for routes belonging to other edges; it only
// notes them (cross-edge visitor locating) and best-effortly refreshes
// the owning client UI. It can never fail a generation: remote routes do
// not touch local router/port/policy state.
type Applier interface {
	OnSnapshot(routes []Route) error
	OnLocalDelta(d Delta) error
	OnRemoteDelta(d Delta)
}

// RPC is the narrow subset of pb.ConfigClient the edge uses.
// bffedgeclient.ConfigAdapter (which wraps bff_edge.BFFEdgeClient.
// SubscribeConfig) satisfies the same shape, so the edge can pick
// either upstream at boot.
type RPC interface {
	Subscribe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], error)
}

// Client maintains the subscription. Start spawns the goroutine; Close
// shuts it down.
type Client struct {
	addr       string
	edgeNodeID int64
	region     string
	version    string
	logger     *slog.Logger
	applier    Applier

	conn   *grpc.ClientConn // nil when StartWithClient was used
	rpc    RPC
	cancel context.CancelFunc

	// store persists the confirmed cursor across process restarts. May be
	// nil (in-memory behavior — safe but every cold boot re-baselines).
	store CursorStore

	curMu sync.Mutex
	cur   Cursor

	// backoff is the initial reconnect delay; doubled up to 30s. Overridable
	// from tests so a forced resync does not cost a real second.
	backoff time.Duration
}

// Options configures the client.
type Options struct {
	Addr       string // host:port of config-svc
	EdgeNodeID int64
	Region     string
	Version    string
	// Applier is called for each parsed snapshot/delta. nil = log only.
	Applier Applier
	// CursorPath, when non-empty, is a state.dir file where the confirmed
	// generation is durably persisted (atomic temp+rename). Empty keeps the
	// cursor in process memory only.
	CursorPath string
	// MinBackoff overrides the initial reconnect backoff (tests); 0 keeps
	// the 1s default.
	MinBackoff time.Duration
}

var (
	// errResyncRequired ends runOnce whenever the edge and the server
	// disagree about stream position or a generation could not be
	// applied. The outer loop reconnects with the persisted cursor.
	errResyncRequired = errors.New("configclient: resync from confirmed cursor required")
)

// StartWithClient is Start's sibling for bff-edge mode: the caller
// passes a pre-made RPC (typically bffedgeclient.NewConfigAdapter) so
// the subscription flows through the shared bff-edge connection instead
// of dialling config-svc directly.
func StartWithClient(parent context.Context, logger *slog.Logger, rpc RPC, opts Options) (*Client, error) {
	if rpc == nil {
		return nil, fmt.Errorf("configclient: nil RPC")
	}
	c := &Client{
		edgeNodeID: opts.EdgeNodeID,
		region:     opts.Region,
		version:    opts.Version,
		logger:     logger.With("component", "configclient"),
		applier:    opts.Applier,
		rpc:        rpc,
		backoff:    opts.MinBackoff,
	}
	if c.backoff <= 0 {
		c.backoff = 1 * time.Second
	}
	if opts.CursorPath != "" {
		c.store = NewFileCursorStore(opts.CursorPath)
		if loaded, err := c.store.Load(); err != nil {
			logger.Warn("config cursor load failed; starting unconfirmed",
				"path", opts.CursorPath, "err", err)
		} else if !loaded.isZero() {
			c.cur = loaded
			logger.Info("config cursor recovered",
				"snapshot_sha", loaded.SnapshotSHA,
				"seq", loaded.Seq,
				"delta_id", loaded.DeltaID)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	go c.runLoop(ctx)
	return c, nil
}

// Close stops the subscription goroutine and closes the gRPC connection
// when this Client owns one. No-op on the conn for StartWithClient
// instances (the caller owns the shared conn).
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// ConfirmedCursor returns a copy of the last confirmed stream position.
func (c *Client) ConfirmedCursor() Cursor {
	c.curMu.Lock()
	defer c.curMu.Unlock()
	return c.cur
}

// confirm advances the confirmed generation and durably persists it
// BEFORE any ack is sent (write-ahead). A persist failure is loud but
// non-fatal: this process stays correct and the next reconnect simply
// re-baselines from a snapshot, same as a node without a state.dir.
func (c *Client) confirm(next Cursor) {
	c.curMu.Lock()
	c.cur = next
	c.curMu.Unlock()
	if c.store != nil {
		if err := c.store.Save(next); err != nil {
			c.logger.Warn("config cursor persist failed; in-process state is correct "+
				"but a restart will re-baseline from a snapshot", "err", err)
		}
	}
}

// runLoop opens the bidi stream and reconnects on transient errors.
func (c *Client) runLoop(ctx context.Context) {
	backoff := c.backoff
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Warn("config stream ended; will reconnect",
				"err", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		// Clean disconnect (ctx.Done() inside runOnce) -> exit loop.
		return
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	stream, err := c.rpc.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// Resume from the confirmed position. An empty sha tells the server
	// to answer with a full snapshot (first connection / cold cursor).
	cur := c.ConfirmedCursor()
	if err := stream.Send(&pb.EdgeMessage{
		Kind: &pb.EdgeMessage_Hello{
			Hello: &pb.HelloEdge{
				EdgeNodeId:         c.edgeNodeID,
				Region:             c.region,
				Version:            c.version,
				CurrentSnapshotSha: cur.SnapshotSHA,
			},
		},
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	if cur.isZero() {
		c.logger.Info("config subscribe hello (no cursor; expecting full snapshot)")
	} else {
		c.logger.Info("config subscribe hello (resuming)",
			"snapshot_sha", cur.SnapshotSHA, "seq", cur.Seq)
	}

	// Heartbeats every 30s so the stream stays warm and config-svc can
	// notice dead edges.
	hbStop := make(chan struct{})
	go c.heartbeat(stream, hbStop)
	defer close(hbStop)

	// basisSet marks whether THIS stream connection has already anchored a
	// generation (snapshot applied or a delta accepted). It keeps a stale
	// snapshot delivered mid-stream from replacing a newer view.
	basisSet := false

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.GetKind().(type) {
		case *pb.ConfigMessage_Snapshot:
			next, routes, perr := decodeSnapshotBody(m.Snapshot)
			if perr != nil {
				c.logger.Warn("snapshot decode failed; refusing to replace local state",
					"sha", m.Snapshot.GetSha(), "err", perr)
				_ = c.nack(stream, next.DeltaID, perr, cur)
				return fmt.Errorf("snapshot decode: %w: %w", perr, errResyncRequired)
			}
			// Carry the wire sha even for a legacy (bare-list) body.
			next.SnapshotSHA = m.Snapshot.GetSha()

			// Anti-regression: a snapshot at an older generation than the
			// one already confirmed must never overwrite newer deltas. A
			// legacy body (Generation==0) cannot be ordered numerically, so
			// it is accepted only as the first basis of a fresh stream — the
			// server sends one precisely because resume failed.
			if next.Seq > 0 && cur.Seq > 0 && next.Seq < cur.Seq {
				c.logger.Warn("stale snapshot refused; resyncing from confirmed cursor",
					"snapshot_gen", next.Seq, "confirmed_seq", cur.Seq)
				return fmt.Errorf("stale snapshot gen=%d < confirmed=%d: %w",
					next.Seq, cur.Seq, errResyncRequired)
			}
			if basisSet && next.Seq == cur.Seq &&
				next.SnapshotSHA == cur.SnapshotSHA && next.SnapshotSHA != "" {
				c.logger.Info("duplicate snapshot for confirmed generation; ignoring",
					"sha", next.SnapshotSHA, "seq", next.Seq)
				continue
			}

			c.logger.Info("config snapshot received",
				"sha", next.SnapshotSHA, "gen", next.Seq, "routes", len(routes))
			if c.applier != nil {
				if aerr := c.applier.OnSnapshot(routes); aerr != nil {
					c.logger.Warn("snapshot apply failed; local state compensated to confirmed generation",
						"sha", next.SnapshotSHA, "gen", next.Seq, "err", aerr)
					_ = c.nack(stream, next.DeltaID, aerr, cur)
					return fmt.Errorf("snapshot apply: %w: %w", aerr, errResyncRequired)
				}
			}
			c.confirm(next)
			cur = next
			basisSet = true

		case *pb.ConfigMessage_Delta:
			wireID := m.Delta.GetDeltaId()
			var delta Delta
			if err := json.Unmarshal(m.Delta.GetPatchJson(), &delta); err != nil {
				// Parse failure: do NOT touch local state and do NOT ack
				// success. Ask the server to replay from the confirmed
				// position after reconnect.
				c.logger.Warn("delta decode failed; requesting replay after confirmed generation",
					"delta_id", wireID, "err", err)
				_ = c.nack(stream, wireID, err, cur)
				return fmt.Errorf("delta %s decode: %w: %w", wireID, err, errResyncRequired)
			}
			seq := delta.ID
			if seq == 0 {
				// Legacy hub whose JSON id is absent: accept a numeric
				// delta_id as the sequence; otherwise ordering is unavailable.
				if n, perr := strconv.ParseUint(wireID, 10, 64); perr == nil {
					seq = n
				}
			}

			// Duplicate / re-delivery of an already-confirmed generation
			// (typically our ack was lost with the stream): re-ack WITHOUT
			// re-applying. Re-running side effects could regress state even
			// when they look idempotent.
			if seq > 0 {
				if seq < cur.Seq {
					c.logger.Debug("old delta behind confirmed cursor; ignoring",
						"delta_id", wireID, "seq", seq, "confirmed_seq", cur.Seq)
					_ = c.ack(stream, wireID)
					continue
				}
				if seq == cur.Seq {
					c.logger.Info("duplicate delta for confirmed generation; re-acking",
						"delta_id", wireID, "seq", seq)
					_ = c.ack(stream, wireID)
					continue
				}
				if seq > cur.Seq+1 {
					if cur.Seq == 0 {
						// Legacy anchor: the snapshot named no generation
						// (bare-list body), so the hub's first numeric
						// delta may start at any offset. Trust it as the
						// sequence anchor; continuity is enforced from
						// this point on.
						c.logger.Info("anchoring config generation at legacy delta id",
							"delta_id", wireID, "seq", seq)
					} else {
						c.logger.Warn("delta gap detected; resyncing from confirmed cursor",
							"delta_id", wireID, "seq", seq,
							"confirmed_seq", cur.Seq)
						_ = c.nack(stream, wireID,
							fmt.Errorf("gap: got seq %d, expected %d", seq, cur.Seq+1), cur)
						return fmt.Errorf("delta gap seq=%d, confirmed=%d: %w",
							seq, cur.Seq, errResyncRequired)
					}
				}
			}
			// Parent-basis guard: when both sides name a snapshot sha they
			// must agree, otherwise the delta builds on state we do not have.
			if parent := m.Delta.GetParentSha(); parent != "" && cur.SnapshotSHA != "" &&
				parent != cur.SnapshotSHA {
				c.logger.Warn("delta parent snapshot mismatch; resyncing",
					"delta_id", wireID, "parent_sha", parent,
					"confirmed_sha", cur.SnapshotSHA)
				_ = c.nack(stream, wireID,
					fmt.Errorf("parent snapshot %q != confirmed %q", parent, cur.SnapshotSHA), cur)
				return fmt.Errorf("delta parent mismatch: %w", errResyncRequired)
			}

			local := delta.Route.EdgeNodeID == c.edgeNodeID
			c.logger.Info("config delta received",
				"id", wireID, "seq", seq,
				"kind", delta.Kind,
				"local", local,
				"route_id", delta.Route.ID,
				"edge", delta.Route.EdgeNodeID,
				"domain", delta.Route.Domain,
			)

			if c.applier != nil {
				var aerr error
				if local {
					aerr = c.applier.OnLocalDelta(delta)
				} else {
					// Remote routes only locate visitor traffic; they never
					// fail a generation (best-effort, original behavior).
					c.applier.OnRemoteDelta(delta)
				}
				if aerr != nil {
					// The applier has already compensated local state back
					// to `cur`. Refuse the generation and recover from the
					// confirmed position.
					c.logger.Warn("delta apply failed; compensated to previous generation",
						"delta_id", wireID, "seq", seq, "err", aerr)
					_ = c.nack(stream, wireID, aerr, cur)
					return fmt.Errorf("delta %s apply: %w: %w", wireID, aerr, errResyncRequired)
				}
			}

			next := cur
			next.Seq = seq
			next.DeltaID = wireID
			// Persist before the ack: a crash here replays the delta as a
			// duplicate (idempotent skip + re-ack), never skips it.
			c.confirm(next)
			cur = next
			basisSet = true
			if err := c.ack(stream, wireID); err != nil {
				// Ack never reached the server; reconnect and let the
				// duplicate-delivery path re-answer it.
				return fmt.Errorf("send ack %s: %w", wireID, err)
			}

		default:
			// No-op server messages (e.g. no-change heartbeats): neither
			// advance the generation nor require an ack.
			c.logger.Debug("unhandled config message", "kind", fmt.Sprintf("%T", msg.GetKind()))
		}
	}
}

// decodeSnapshotBody accepts the generation-carrying envelope
// ({"generation":N,"delta_id":"…","routes":[…]}) and the legacy bare
// JSON array of Route.
func decodeSnapshotBody(s *pb.Snapshot) (Cursor, []Route, error) {
	body := s.GetBodyJson()
	cur := Cursor{SnapshotSHA: s.GetSha()}
	if len(body) == 0 {
		return cur, nil, nil
	}
	trimmed := body
	// Cheap shape detection; fall through to json.Unmarshal either way so
	// whitespace/object-ordering quirks stay in the decoder's hands.
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\n' || trimmed[0] == '\t' || trimmed[0] == '\r') {
		trimmed = trimmed[1:]
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var env snapshotEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			return cur, nil, err
		}
		cur.Seq = env.Generation
		cur.DeltaID = env.DeltaID
		return cur, env.Routes, nil
	}
	var routes []Route
	if err := json.Unmarshal(body, &routes); err != nil {
		return cur, nil, err
	}
	return cur, routes, nil
}

// ack confirms one delta generation.
func (c *Client) ack(stream grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], deltaID string) error {
	return stream.Send(&pb.EdgeMessage{
		Kind: &pb.EdgeMessage_Ack{
			Ack: &pb.Ack{DeltaId: deltaID, Ok: true},
		},
	})
}

// nack refuses one generation and tells the server where the edge's
// confirmed stream actually ends, so the reconnect can resume there (or
// substitute a full snapshot when resume is impossible). Best-effort:
// if the nack itself cannot be sent, the stream teardown that follows
// carries the same request on the next hello.
func (c *Client) nack(stream grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage],
	deltaID string, cause error, confirmed Cursor) error {
	return stream.Send(&pb.EdgeMessage{
		Kind: &pb.EdgeMessage_Ack{
			Ack: &pb.Ack{
				DeltaId: deltaID,
				Ok:      false,
				Error: fmt.Sprintf("apply failed: %v; resume after snapshot_sha=%q seq=%d",
					cause, confirmed.SnapshotSHA, confirmed.Seq),
			},
		},
	})
}

func (c *Client) heartbeat(stream grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = stream.Send(&pb.EdgeMessage{
				Kind: &pb.EdgeMessage_Beat{
					Beat: &pb.Heartbeat{Ts: timestamppb.Now()},
				},
			})
		}
	}
}
