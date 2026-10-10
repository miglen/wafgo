package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// checkedWriter retains the first output failure, including a short write, so
// callers that render with fmt can report a failing exit status afterwards.
type checkedWriter struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func (w *checkedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, err := w.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func (w *checkedWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// writeFileAtomic replaces a regular file only after its new contents have been
// written, synced, and closed successfully. New files are private; replacements
// retain the existing file's permissions. Symlinks and special files are refused.
func writeFileAtomic(path string, write func(io.Writer) error) error {
	info, err := reportDestination(path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if info != nil {
		if err := f.Chmod(info.Mode().Perm()); err != nil {
			return err
		}
	}
	if err := write(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Recheck after writing in case the destination became a link or special file.
	if _, err := reportDestination(path); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func reportDestination(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to overwrite symbolic link %q", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to overwrite non-regular file %q", path)
	}
	return info, nil
}
