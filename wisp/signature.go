package wisp

import (
	"fmt"
	"strings"
	"time"
)

func NewSignatures(cfg SignatureConfig) *Signatures {
	return &Signatures{cfg: cfg, per: make(map[string]*Detector)}
}

func (s *Signatures) For(connID uint64, dstIP string, dstPort int) *Detector {
	if s == nil || !s.cfg.Enabled {
		return nopDetector
	}
	key := fmt.Sprintf("%d|%s:%d", connID, dstIP, dstPort)
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.per[key]
	if !ok {
		d = &Detector{cfg: s.cfg}
		s.per[key] = d
	}
	return d
}

func (s *Signatures) Forget(connID uint64) {
	if s == nil {
		return
	}
	prefix := fmt.Sprintf("%d|", connID)
	s.mu.Lock()
	for k := range s.per {
		if strings.HasPrefix(k, prefix) {
			delete(s.per, k)
		}
	}
	s.mu.Unlock()
}

var nopDetector = &Detector{}

func (d *Detector) Record(ok bool) {
	if d == nil || d.cfg.Window == 0 {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ring = append(d.ring, sample{now, ok})
	cutoff := now.Add(-d.cfg.Window)
	for len(d.ring) > 0 && d.ring[0].t.Before(cutoff) {
		d.ring = d.ring[1:]
	}
}

func (d *Detector) Match() bool {
	if d == nil || d.cfg.Window == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ring) < d.cfg.MinSamples {
		return false
	}
	failed := 0
	for _, s := range d.ring {
		if !s.ok {
			failed++
		}
	}
	ratio := float64(failed) / float64(len(d.ring))
	return ratio >= d.cfg.FailedHandshakeRatio
}
