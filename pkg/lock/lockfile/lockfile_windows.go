// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lockfile

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Lockfile provides cross-process file locking on Windows using
// LockFileEx/UnlockFileEx.
type Lockfile struct {
	fp *os.File
}

// NewLockfile creates and opens a lockfile, but does not acquire a lock.
func NewLockfile(path string) (*Lockfile, error) {
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create lockfile %s: %w", path, err)
	}

	return &Lockfile{
		fp: fp,
	}, nil
}

// Close will close the file, which implicitly removes all locks held.
// It is an error to re-use a closed Lockfile.
func (l *Lockfile) Close() error {
	fp := l.fp
	l.fp = nil
	return fp.Close()
}

// TryLock will attempt to take a lock, returning error if it is not
// possible to acquire the lock.
// If exclusive is true, then it will attempt to obtain a write, or exclusive, lock.
func (l *Lockfile) TryLock(exclusive bool) error {
	return l.lockFile(context.Background(), exclusive, false)
}

// Lock will attempt to take a lock, blocking until it is able to do so.
// If exclusive is true, then it will obtain a write, or exclusive, lock.
func (l *Lockfile) Lock(ctx context.Context, exclusive bool) error {
	return l.lockFile(ctx, exclusive, true)
}

// Unlock removes the lock, but keeps the file open.
func (l *Lockfile) Unlock() error {
	h := windows.Handle(l.fp.Fd())
	ol := new(windows.Overlapped)
	// Unlock the entire file (offset 0, length 1 byte — matching the lock range).
	return windows.UnlockFileEx(h, 0, 1, 0, ol)
}

// lockFile performs the lock operation using Windows LockFileEx.
func (l *Lockfile) lockFile(ctx context.Context, exclusive, wait bool) error {
	h := windows.Handle(l.fp.Fd())
	ol := new(windows.Overlapped)

	var flags uint32
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}

	// If no context or non-cancellable context, do a direct call.
	if ctx.Done() == nil {
		return windows.LockFileEx(h, flags, 0, 1, 0, ol)
	}

	// LockFileEx is blocking, so wrap it in a goroutine to support context cancellation.
	lockCh := make(chan error, 1)
	go func() {
		lockCh <- windows.LockFileEx(h, flags, 0, 1, 0, ol)
	}()

	select {
	case err := <-lockCh:
		return err
	case <-ctx.Done():
		// We can't cancel the syscall, but we can unlock if it succeeds.
		go func() {
			if err := <-lockCh; err == nil {
				l.Unlock()
			}
		}()
		return ctx.Err()
	}
}
