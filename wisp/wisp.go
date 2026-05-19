package wisp

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lxzan/gws"
)

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultMaxConnectsPerSecond  = 20
	defaultConnectionsLimitPerIP = 120
	defaultHandshakeFailures     = 10
)

func (cfg *Config) InitResolver() {
	cfg.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     cfg.DnsServers,
			Method:      cfg.DnsMethod,
			ResultOrder: cfg.DnsResultOrder,
		})
	cfg.Logger = newLogger(cfg.LogLevel)
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = &sync.Pool{
		New: func() any {
			buf := make([]byte, readBufSize)
			return &buf
		},
	}

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: false,
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
			return
		}

		netConn := wsConn.NetConn()

		if tc, ok := netConn.(*net.TCPConn); ok {
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		wc := &wispConnection{
			netConn:      netConn,
			writeCh:      make(chan writeReq, 4096), // funny number
			config:       config,
			twispStreams: newTwisp(),
			isV2:         useV2,
		}

		go wc.writeLoop()

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}

func (cfg *Config) requiresV2() bool {
	if cfg == nil {
		return false
	}
	return cfg.PasswordAuthRequired || cfg.EnableTwisp
}
