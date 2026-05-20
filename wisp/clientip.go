package wisp

import (
	"net"
	"net/http"
	"strings"
)

func ResolveClientIP(r *http.Request, trustedProxies []*net.IPNet, headers []string) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return net.IPv4zero
	}

	if !ipInAny(peer, trustedProxies) {
		return peer
	}

	for _, h := range headers {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		parts := strings.Split(v, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(parts[i]))
			if candidate == nil {
				continue
			}
			if ipInAny(candidate, trustedProxies) {
				continue
			}
			return candidate
		}
	}
	return peer
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
