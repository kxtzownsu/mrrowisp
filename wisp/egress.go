package wisp

import "net"

func PolicyFromConfig(cfg *Config) *EgressPolicy {
	return &EgressPolicy{
		AllowLoopback: cfg.AllowLoopbackIPs,
		AllowPrivate:  cfg.AllowPrivateIPs,
	}
}

func (p *EgressPolicy) Evaluate(ip net.IP) (bool, string) {
	if p == nil {
		return true, ""
	}
	if ip == nil {
		return false, "invalid"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if p.DenyIPs != nil {
		if _, ok := p.DenyIPs[ip.String()]; ok {
			return false, "deny_ip"
		}
	}
	for _, n := range p.DenyCIDRs {
		if n.Contains(ip) {
			return false, "deny_cidr"
		}
	}

	explicitAllow := false
	if p.AllowIPs != nil {
		if _, ok := p.AllowIPs[ip.String()]; ok {
			explicitAllow = true
		}
	}
	if !explicitAllow {
		for _, n := range p.AllowCIDRs {
			if n.Contains(ip) {
				explicitAllow = true
				break
			}
		}
	}
	if explicitAllow {
		return true, ""
	}

	if ip.IsUnspecified() {
		return false, "unspecified"
	}
	if ip.IsLoopback() {
		if p.AllowLoopback {
			return true, ""
		}
		return false, "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "link_local"
	}
	if ip.IsPrivate() {
		if p.AllowPrivate {
			return true, ""
		}
		return false, "private"
	}
	if ip.IsMulticast() {
		return false, "multicast"
	}
	return true, ""
}
