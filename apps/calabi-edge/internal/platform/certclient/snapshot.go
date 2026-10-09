// snapshot.go — the on-disk, encrypted, atomically-published recovery
// record of the last CONFIRMED cert generation.
//
// WHY THIS EXISTS
// ---------------
// A refresh that only fetched part of the catalog used to swap the serving
// pool for the incomplete one anyway; when the event stream then dropped or
// the process restarted, domains that were fine a moment ago started failing
// TLS handshakes. Every committed generation therefore writes enough state
// here to serve it again WITHOUT the control plane:
//
//   - every entry's fullchain + DECRYPTED private key PEM (the same bytes
//     GetCert handed us), plus the SAN/CN/fingerprint/version metadata;
//   - the delete tombstones, so a cert confirmed deleted cannot be
//     resurrected by events replayed after a restart;
//   - the local commit seq, so the generation clock continues monotonically.
//
// ENCRYPTION
// ----------
// The file holds decrypted private keys, so it is sealed with AES-256-GCM.
// The key is a random 32 bytes generated on first use and kept in a 0600
// sibling file in the same state directory. That keeps private keys out of
// world-readable files and off any backup that takes the pool file without
// the key; the node operator already owns the cert-svc-issued edge key that
// can fetch every one of these private keys again, so a lost snapshot key
// degrades to "cold refetch", never to a weaker on-disk posture.
//
// ATOMICITY — FAILURE MODES
// -------------------------
// Publication is temp-file + fsync + rename in the SAME directory: a crash
// or a full disk mid-write leaves the previously confirmed file byte-for-byte
// in place ("snapshot publish failed → keep the old snapshot"). A generation
// is "confirmed" once it is serving in memory; the snapshot write is
// best-effort on top of that, and a later tick retries it. On startup with
// the control plane unreachable, the last confirmed snapshot is loaded and
// served; a corrupt/tampered/unreadable snapshot is refused wholesale
// (never partially applied) and the node starts cold instead.

package certclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	// snapshotFileName is the sealed generation record under state.dir.
	snapshotFileName = "cert-pool.enc"
	// snapshotKeyFileName is the 0600 AES-256 key next to it.
	snapshotKeyFileName = "cert-pool.key"

	// snapshotMagic prefixes every sealed file so a wrong/old format fails
	// loudly instead of being fed to AES. 8 bytes, fixed.
	snapshotMagic = "CALCRT01"
	snapshotNonce = 12 // AES-GCM standard nonce size
)

// snapshotStore owns the paths of the sealed record and its key. A nil
// *snapshotStore disables persistence (no state.dir configured); every
// method is nil-safe so callers don't branch on it.
type snapshotStore struct {
	dir     string
	path    string
	keyPath string
	logger  *slog.Logger
}

func newSnapshotStore(dir string, logger *slog.Logger) *snapshotStore {
	dir = filepath.Clean(dir)
	return &snapshotStore{
		dir:     dir,
		path:    filepath.Join(dir, snapshotFileName),
		keyPath: filepath.Join(dir, snapshotKeyFileName),
		logger:  logger,
	}
}

// snapshotFormat is the JSON body sealed inside the envelope. Bump
// snapshotFormat when the shape changes incompatibly; load refuses a
// format it does not know.
const snapshotFormat = 1

type snapshotFile struct {
	Format      int                       `json:"format"`
	Seq         uint64                    `json:"seq"`
	Entries     []snapshotEntry           `json:"entries"`
	Tombstones  map[int64]int64           `json:"tombstones,omitempty"`
}

type snapshotEntry struct {
	ID            int64    `json:"id"`
	OrgID         int64    `json:"org_id"`
	SANs          []string `json:"sans,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	Version       int64    `json:"version,omitempty"`
	FullchainPEM  []byte   `json:"fullchain_pem"`
	PrivateKeyPEM []byte   `json:"private_key_pem"`
}

// save seals g and publishes it atomically. The previous file is left
// untouched on ANY failure (temp write, seal, fsync, or rename).
func (s *snapshotStore) save(g *generation) error {
	if s == nil {
		return nil
	}
	if g == nil {
		return errors.New("certclient snapshot: refusing to persist nil generation")
	}
	body := snapshotFile{
		Format:     snapshotFormat,
		Seq:        g.seq,
		Tombstones: copyInt64Map(g.tombstones),
		Entries:    make([]snapshotEntry, 0, len(g.entries)),
	}
	// Stable order on disk: not required for correctness, but it makes two
	// snapshots of the same generation byte-comparable and keeps diffs sane.
	for _, id := range sortedInt64Keys(g.entries) {
		e := g.entries[id]
		body.Entries = append(body.Entries, snapshotEntry{
			ID:            e.id,
			OrgID:         e.orgID,
			SANs:          append([]string(nil), e.sans...),
			Subject:       e.subject,
			Fingerprint:   e.fingerprint,
			Version:       e.version,
			FullchainPEM:  append([]byte(nil), e.fullchainPEM...),
			PrivateKeyPEM: append([]byte(nil), e.privateKeyPEM...),
		})
	}
	plain, err := json.Marshal(&body)
	if err != nil {
		return fmt.Errorf("encode generation: %w", err)
	}
	key, err := s.loadOrCreateKey()
	if err != nil {
		return err
	}
	sealed, err := seal(key, plain)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, sealed, 0o600); err != nil {
		return fmt.Errorf("publish snapshot: %w", err)
	}
	return nil
}

// load reads + opens + parses the last confirmed snapshot.
//
// Returns (nil, nil) when no snapshot has ever been written: cold start,
// nothing to recover. Every other failure — bad key, tampered ciphertext,
// unknown format, a keypair that no longer parses — is an error: the caller
// serves nothing rather than half a generation, matching the "all listed
// certs fetched AND parsed before anything is served" rule.
func (s *snapshotStore) load() (*generation, error) {
	if s == nil {
		return nil, nil
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	key, err := os.ReadFile(s.keyPath)
	if err != nil {
		return nil, fmt.Errorf("read snapshot key: %w", err)
	}
	plain, err := open(key, raw)
	if err != nil {
		return nil, err
	}
	var body snapshotFile
	if err := json.Unmarshal(plain, &body); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if body.Format != snapshotFormat {
		return nil, fmt.Errorf("snapshot format %d unsupported, want %d", body.Format, snapshotFormat)
	}
	entries := make(map[int64]*certEntry, len(body.Entries))
	for _, se := range body.Entries {
		tc, err := parsePair(se.FullchainPEM, se.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("snapshot cert %d: %w", se.ID, err)
		}
		entries[se.ID] = &certEntry{
			id:            se.ID,
			orgID:         se.OrgID,
			cert:          tc,
			sans:          append([]string(nil), se.SANs...),
			subject:       se.Subject,
			fingerprint:   se.Fingerprint,
			version:       se.Version,
			fullchainPEM:  append([]byte(nil), se.FullchainPEM...),
			privateKeyPEM: append([]byte(nil), se.PrivateKeyPEM...),
		}
	}
	g := projectGeneration(body.Seq, entries, body.Tombstones)
	if g.seq != body.Seq {
		// projectGeneration must not renumber; this guards a programming error.
		return nil, errors.New("snapshot seq mismatch after projection")
	}
	return g, nil
}

// loadOrCreateKey reads the 0600 sealing key, generating it on first use.
func (s *snapshotStore) loadOrCreateKey() ([]byte, error) {
	if b, err := os.ReadFile(s.keyPath); err == nil {
		if len(b) == 32 {
			return b, nil
		}
		return nil, fmt.Errorf("snapshot key %s is %d bytes, want 32", s.keyPath, len(b))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read snapshot key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate snapshot key: %w", err)
	}
	// Best-effort create the directory: state.dir normally exists, but a
	// fresh dev/test layout may not. 0700 — it holds private-key material.
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir for snapshot key: %w", err)
	}
	if err := writeFileAtomic(s.keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write snapshot key: %w", err)
	}
	return key, nil
}

// writeFileAtomic writes via a same-directory temp file, fsyncs it, then
// renames into place. Same-directory matters: rename across filesystems is
// not atomic, and a crash must leave either the old or the new file whole.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// seal returns snapshotMagic || nonce || gcm(ciphertext||tag).
func seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("snapshot cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(snapshotMagic)+snapshotNonce+len(plaintext)+gcm.Overhead())
	out = append(out, []byte(snapshotMagic)...)
	nonce := out[len(out) : len(out)+snapshotNonce]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, []byte(snapshotMagic))
	return out, nil
}

// open reverses seal, verifying the magic header and the GCM tag.
func open(key, raw []byte) ([]byte, error) {
	if len(raw) < len(snapshotMagic)+snapshotNonce+16 {
		return nil, errors.New("snapshot file too short")
	}
	if string(raw[:len(snapshotMagic)]) != snapshotMagic {
		return nil, errors.New("not a calabi cert snapshot (bad magic)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("snapshot cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := raw[len(snapshotMagic) : len(snapshotMagic)+snapshotNonce]
	sealed := raw[len(snapshotMagic)+snapshotNonce:]
	plain, err := gcm.Open(nil, nonce, sealed, []byte(snapshotMagic))
	if err != nil {
		return nil, fmt.Errorf("snapshot unseal failed (wrong key or tampered): %w", err)
	}
	return plain, nil
}
