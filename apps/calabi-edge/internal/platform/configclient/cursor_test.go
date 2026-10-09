package configclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileCursorSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileCursorStore(filepath.Join(dir, "nested", "config-cursor.json"))

	want := Cursor{SnapshotSHA: "sha-abc", Seq: 42, DeltaID: "d-42"}
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SnapshotSHA != want.SnapshotSHA || got.Seq != want.Seq || got.DeltaID != want.DeltaID {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", got, want)
	}
	if got.UpdatedAt == 0 {
		t.Fatal("UpdatedAt should be stamped on save")
	}
}

func TestFileCursorLoadMissingIsZero(t *testing.T) {
	s := NewFileCursorStore(filepath.Join(t.TempDir(), "absent.json"))
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if !got.isZero() {
		t.Fatalf("missing cursor should be zero, got %+v", got)
	}
}

func TestFileCursorLoadCorruptResetsToZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-cursor.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewFileCursorStore(path)
	got, err := s.Load()
	if err != nil {
		t.Fatalf("corrupt cursor must not error: %v", err)
	}
	if !got.isZero() {
		t.Fatalf("corrupt cursor should reset to zero, got %+v", got)
	}
}
