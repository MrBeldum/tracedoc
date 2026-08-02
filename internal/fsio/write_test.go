package fsio

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAtomicOutput(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "nested", "matrix.md")
	if err := WriteFileAtomic(outputPath, []byte("first\n")); err != nil {
		t.Fatalf("create atomic output: %v", err)
	}
	if err := WriteFileAtomic(outputPath, []byte("second\n")); err != nil {
		t.Fatalf("replace atomic output: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read atomic output: %v", err)
	}
	if string(data) != "second\n" {
		t.Fatalf("unexpected atomic output %q", data)
	}
	if info, err := os.Stat(outputPath); err != nil {
		t.Fatalf("stat atomic output: %v", err)
	} else if info.Mode().Perm() != 0o644 {
		t.Fatalf("expected mode 0644, got %o", info.Mode().Perm())
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(outputPath), ".matrix.md.tmp-*")); err != nil {
		t.Fatalf("glob temporary files: %v", err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary files remain: %q", matches)
	}
}

func TestAtomicOutputReplacesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink replacement semantics differ on Windows")
	}
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "target.md")
	outputPath := filepath.Join(directory, "matrix.md")
	if err := os.WriteFile(targetPath, []byte("target\n"), 0o644); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, outputPath); err != nil {
		t.Fatalf("create output symlink: %v", err)
	}
	if err := WriteFileAtomic(outputPath, []byte("rendered\n")); err != nil {
		t.Fatalf("replace symlink: %v", err)
	}
	if info, err := os.Lstat(outputPath); err != nil {
		t.Fatalf("lstat output: %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("atomic output followed the destination symlink")
	}
	if target, err := os.ReadFile(targetPath); err != nil {
		t.Fatalf("read symlink target: %v", err)
	} else if string(target) != "target\n" {
		t.Fatalf("symlink target was modified: %q", target)
	}
}

func TestAtomicOutputCleansUpAfterRenameFailure(t *testing.T) {
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "matrix.md")
	if err := os.Mkdir(outputPath, 0o755); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}
	sentinel := filepath.Join(outputPath, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged\n"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	if err := WriteFileAtomic(outputPath, []byte("rendered\n")); err == nil {
		t.Fatal("expected rename to a non-empty directory to fail")
	}
	if data, err := os.ReadFile(sentinel); err != nil {
		t.Fatalf("read sentinel after failure: %v", err)
	} else if string(data) != "unchanged\n" {
		t.Fatalf("destination changed after failed rename: %q", data)
	}
	if matches, err := filepath.Glob(filepath.Join(directory, ".matrix.md.tmp-*")); err != nil {
		t.Fatalf("glob temporary files: %v", err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary files remain after failure: %q", matches)
	}
}

// TestAtomicOutputReadOnlyParentDirectoryFails checks that a permission
// failure creating the same-directory temporary file (rather than a
// rename failure, covered above) is also surfaced as an error, not
// swallowed or panicked on. Root and Windows both ignore or do not apply
// directory write-permission bits the way this test expects, so it is
// skipped there.
func TestAtomicOutputReadOnlyParentDirectoryFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write permissions are not enforced the same way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}

	parent := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("create parent directory: %v", err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatalf("make parent directory read-only: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatalf("restore parent directory permissions: %v", err)
		}
	})

	outputPath := filepath.Join(parent, "matrix.md")
	if err := WriteFileAtomic(outputPath, []byte("rendered\n")); err == nil {
		t.Fatal("expected write into a read-only parent directory to fail")
	}
}
