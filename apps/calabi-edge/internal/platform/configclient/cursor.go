package configclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cursor is the edge's last CONFIRMED position in the config stream.
//
// It is the only state the edge is allowed to "believe" across a stream
// interruption or a process restart: a generation is confirmed only after
// every local apply step (router, port occupancy, policy, and the
// CONFIG_PUSH to online clients) has succeeded and the ack has gone out.
// The cursor is persisted BEFORE the ack is sent, so on restart the edge
// asks the server to resume deltas from exactly here rather than trusting
// whatever snapshot the reconnect happens to deliver.
//
// Field semantics:
//
//   - SnapshotSHA is the sha of the base snapshot the confirmed deltas
//     descend from. It is also the resume token carried in
//     HelloEdge.current_snapshot_sha ("" = no snapshot yet -> the server
//     must send a full one).
//   - Seq is the continuous delta-log sequence (Delta.ID); 0 when talking
//     to a server that predates generation-carrying payloads, in which
//     case ordering falls back to delta-id dedupe only.
//   - DeltaID is the wire ack token (Delta.delta_id) at Seq, retained so
//     a duplicate delivery after an ack loss can be answered without
//     re-applying anything.
type Cursor struct {
	SnapshotSHA string `json:"snapshot_sha"`
	Seq         uint64 `json:"seq"`
	DeltaID     string `json:"delta_id,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// isZero reports whether no generation has been confirmed yet (a first
// connection, which must ask for a full snapshot).
func (c Cursor) isZero() bool { return c.SnapshotSHA == "" && c.Seq == 0 && c.DeltaID == "" }

// CursorStore persists the confirmed cursor. Implementations MUST survive
// ordinary process exits (durable media); a nil store degrades to
// process-lifetime memory only.
type CursorStore interface {
	Load() (Cursor, error)
	Save(Cursor) error
}

// FileCursorStore keeps the cursor as one small JSON file, written
// atomically (temp file + rename) so a crash mid-write leaves either the
// old cursor or the new one, never a torn document. This is the same
// durability dance router.SubdomainAllocator uses for its seq file.
type FileCursorStore struct{ path string }

// NewFileCursorStore returns a store rooted at path (the parent directory
// is created lazily on Save). It does NOT read the file here: callers may
// construct the store before the state directory exists.
func NewFileCursorStore(path string) *FileCursorStore {
	return &FileCursorStore{path: path}
}

// Load returns the stored cursor. A missing file is a zero cursor, not an
// error — the usual first-boot case.
func (s *FileCursorStore) Load() (Cursor, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Cursor{}, nil
		}
		return Cursor{}, fmt.Errorf("config-cursor: read %s: %w", s.path, err)
	}
	var c Cursor
	if err := json.Unmarshal(data, &c); err != nil {
		// A corrupt file must not wedge the subscription: return a zero
		// cursor so the edge re-baselines with a full snapshot and overwrites
		// the bad file on the next confirmation.
		return Cursor{}, nil
	}
	return c, nil
}

// Save writes c atomically with 0644 perms.
func (s *FileCursorStore) Save(c Cursor) error {
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("config-cursor: mkdir %s: %w", dir, err)
		}
	}
	c.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config-cursor: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("config-cursor: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("config-cursor: rename: %w", err)
	}
	return nil
}
