package wisp

import (
	"sync/atomic"
	"time"
)

func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		limit:   limit,
		window:  window,
		entries: make(map[string]*windowEntry),
	}
}

func (w *SlidingWindow) Allow(key string) bool {
	if w == nil || w.limit <= 0 {
		return true
	}
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[key]
	if !ok || now.Sub(e.start) >= w.window {
		w.entries[key] = &windowEntry{start: now, count: 1}
		return true
	}
	e.count++
	return e.count <= w.limit
}

func (w *SlidingWindow) Evict(idle time.Duration) {
	if w == nil {
		return
	}
	cutoff := time.Now().Add(-idle)
	w.mu.Lock()
	for k, e := range w.entries {
		if e.start.Before(cutoff) {
			delete(w.entries, k)
		}
	}
	w.mu.Unlock()
}

func NewSemaphore(max int) *Semaphore {
	return &Semaphore{max: int64(max)}
}

func (s *Semaphore) TryAcquire() bool {
	if s == nil || s.max <= 0 {
		return true
	}
	for {
		cur := atomic.LoadInt64(&s.current)
		if cur >= s.max {
			return false
		}
		if atomic.CompareAndSwapInt64(&s.current, cur, cur+1) {
			return true
		}
	}
}

func (s *Semaphore) Release() {
	if s == nil || s.max <= 0 {
		return
	}
	atomic.AddInt64(&s.current, -1)
}
