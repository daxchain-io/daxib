package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicCreatesAt0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	if err := WriteAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("content = %q, want hello", b)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %#o, want 0600", perm)
	}
}

func TestWriteAtomicOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	if err := WriteAtomic(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteAtomic(path, []byte("new-and-longer"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "new-and-longer" {
		t.Errorf("content = %q, want new-and-longer", b)
	}
}

// TestWriteAtomicNoTempLeftovers asserts the temp file is cleaned up so the
// directory only holds the final file after a successful write.
func TestWriteAtomicNoTempLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	if err := WriteAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "data.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir entries = %v, want only data.json", names)
	}
}

func TestMkdirAll(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	if err := MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fi, err := os.Stat(nested)
	if err != nil || !fi.IsDir() {
		t.Fatalf("nested dir not created: %v", err)
	}
}
