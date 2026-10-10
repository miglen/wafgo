package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestCheckedWriterSkipsEmptyOutput(t *testing.T) {
	w := &checkedWriter{w: failingWriter{errors.New("unused output is unavailable")}}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty output: n=%d err=%v", n, err)
	}
	if err := w.Err(); err != nil {
		t.Fatalf("empty output recorded a failure: %v", err)
	}
}

func TestCLIReportsOutputFailures(t *testing.T) {
	writeErr := errors.New("output unavailable")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"version", []string{"--version"}},
		{"list text", []string{"--list"}},
		{"list JSON", []string{"--list", "--format", "json"}},
	} {
		for _, failure := range []struct {
			name string
			w    io.Writer
			want string
		}{
			{"write error", failingWriter{writeErr}, writeErr.Error()},
			{"short write", shortWriter{}, io.ErrShortWrite.Error()},
		} {
			t.Run(tc.name+"/"+failure.name, func(t *testing.T) {
				var stderr bytes.Buffer
				code := run(context.Background(), tc.args, strings.NewReader(""), failure.w, &stderr)
				if code != exitError || !strings.Contains(stderr.String(), failure.want) {
					t.Fatalf("code=%d stderr=%q; want output error %q", code, stderr.String(), failure.want)
				}
			})
		}
	}
}

func TestCLIReportsHelpOutputFailure(t *testing.T) {
	code := run(context.Background(), []string{"--help"}, strings.NewReader(""), io.Discard,
		failingWriter{errors.New("stderr unavailable")})
	if code != exitError {
		t.Fatalf("code=%d, want %d", code, exitError)
	}
}

func TestCLIOutputFailurePreservesUsageExitCode(t *testing.T) {
	code := run(context.Background(), nil, strings.NewReader(""),
		failingWriter{errors.New("stdout unavailable")}, io.Discard)
	if code != exitUsage {
		t.Fatalf("code=%d, want %d", code, exitUsage)
	}
}

func TestCLIRejectsMalformedJSONBeforeProcessingTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, []byte(`[{"url":"http://["}] trailing`), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := runCLI(t, "-q", "--input-file", path)
	if code != exitError || !strings.Contains(stderr, path) {
		t.Fatalf("code=%d stderr=%q; want input error with filename", code, stderr)
	}
	if out != "" {
		t.Fatalf("unexpected target processing output: %q", out)
	}
}

func TestWriteFileAtomicPreservesPreviousReportOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(io.Writer) error
	}{
		{"write", func(w io.Writer) error {
			_, _ = io.WriteString(w, "partial replacement")
			return errors.New("serialization failed")
		}},
		{"sync", func(w io.Writer) error {
			// Closing the file makes the subsequent sync fail deterministically.
			return w.(*os.File).Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.json")
			const original = "previous report"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if err := writeFileAtomic(path, tc.fail); err == nil {
				t.Fatal("expected save failure")
			}
			assertFileContents(t, path, original)
			assertDirectoryEntries(t, dir, "report.json")
		})
	}
}

func TestWriteFileAtomicPermissions(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new file"
		if existing {
			name = "existing file"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.json")
			wantMode := os.FileMode(0600)
			if existing {
				wantMode = 0640
				if err := os.WriteFile(path, []byte("old"), wantMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, wantMode); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeFileAtomic(path, func(w io.Writer) error {
				_, err := io.WriteString(w, "complete replacement")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			assertFileContents(t, path, "complete replacement")
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != wantMode {
				t.Fatalf("permissions=%#o, want %#o", info.Mode().Perm(), wantMode)
			}
			assertDirectoryEntries(t, dir, "report.json")
		})
	}
}

func TestWriteFileAtomicRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original.json")
	link := filepath.Join(dir, "report.json")
	if err := os.WriteFile(target, []byte("original report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	err := writeFileAtomic(link, func(io.Writer) error {
		t.Fatal("write callback called for a symlink")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected explicit symlink error, got %v", err)
	}
	assertFileContents(t, target, "original report")
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was replaced: info=%v err=%v", info, err)
	}
	assertDirectoryEntries(t, dir, "original.json", "report.json")
}

func TestWriteFileAtomicRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	err := writeFileAtomic(dir, func(io.Writer) error {
		t.Fatal("write callback called for a directory")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("expected non-regular file error, got %v", err)
	}
}

func TestWriteFileAtomicCleansUpAfterDestinationChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	err := writeFileAtomic(path, func(w io.Writer) error {
		if _, err := io.WriteString(w, "replacement"); err != nil {
			return err
		}
		// A directory created at the destination must survive the attempted save.
		return os.Mkdir(path, 0700)
	})
	if err == nil {
		t.Fatal("expected save failure")
	}
	info, statErr := os.Stat(path)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("destination directory was replaced: info=%v err=%v", info, statErr)
	}
	assertDirectoryEntries(t, dir, "report.json")
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("file contents=%q, want %q", got, want)
	}
}

func assertDirectoryEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("directory entries=%v, want %v (temporary files must be removed)", entries, want)
	}
	for i, entry := range entries {
		if entry.Name() != want[i] {
			t.Fatalf("directory entry=%q, want %q", entry.Name(), want[i])
		}
	}
}
