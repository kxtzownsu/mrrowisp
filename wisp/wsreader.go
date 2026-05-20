package wisp

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"
	"unsafe"
)

const wsPayloadPoolSize = 256 * 1024

var wsPayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, wsPayloadPoolSize)
		return &buf
	},
}

func getWSPayloadBuf(size int) *[]byte {
	bufp := wsPayloadPool.Get().(*[]byte)
	if cap(*bufp) < size {
		nb := make([]byte, size)
		return &nb
	}
	*bufp = (*bufp)[:size]
	return bufp
}

func putWSPayloadBuf(bufp *[]byte) {
	if bufp == nil || cap(*bufp) == 0 {
		return
	}
	wsPayloadPool.Put(bufp)
}

func (c *wispConnection) readLoop() {
	defer c.deleteAllWispStreams()
	reader := bufio.NewReaderSize(c.netConn, 512*1024)

	var headerBuffer [14]byte

	for {
		if _, err := io.ReadFull(reader, headerBuffer[:2]); err != nil {
			return
		}

		fin := headerBuffer[0]&0x80 != 0
		rsv := headerBuffer[0] & 0x70
		opcode := headerBuffer[0] & 0x0F
		masked := headerBuffer[1]&0x80 != 0
		lengthCode := headerBuffer[1] & 0x7F

		if rsv != 0 || !masked || !fin {
			c.sendWSClose(1002)
			return
		}

		var payloadLen uint64
		switch {
		case lengthCode <= 125:
			payloadLen = uint64(lengthCode)
		case lengthCode == 126:
			if _, err := io.ReadFull(reader, headerBuffer[2:4]); err != nil {
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(headerBuffer[2:4]))
		case lengthCode == 127:
			if _, err := io.ReadFull(reader, headerBuffer[2:10]); err != nil {
				return
			}
			payloadLen = binary.BigEndian.Uint64(headerBuffer[2:10])
		}

		isControlFrame := opcode >= 0x8
		if isControlFrame && payloadLen > 125 {
			c.sendWSClose(1002)
			return
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(reader, maskKey[:]); err != nil {
				return
			}
		}

		if payloadLen > c.maxPayloadSize() {
			c.sendWSClose(1009)
			return
		}

		bufp := getWSPayloadBuf(int(payloadLen))
		payload := (*bufp)[:payloadLen]

		if payloadLen > 0 {
			if _, err := io.ReadFull(reader, payload); err != nil {
				putWSPayloadBuf(bufp)
				return
			}
		}

		if masked && payloadLen > 0 {
			maskXOR(payload, maskKey)
		}

		keep := false
		switch opcode {
		case 0x2, 0x1:
			keep = c.handleWispFrame(payload, bufp)

		case 0x9:
			_ = c.writeRawPong(payload)

		case 0x8:
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload[:2])
				c.sendWSClose(code)
			} else {
				c.sendWSClose(1000)
			}
			putWSPayloadBuf(bufp)
			return
		default:
			continue
		}

		if !keep {
			putWSPayloadBuf(bufp)
		}
	}
}

const DefaultMaxPayloadSize = 256 * 1024

func (c *wispConnection) maxPayloadSize() uint64 {
	if c != nil && c.config != nil && c.config.MaxMessageSize > 0 {
		return uint64(c.config.MaxMessageSize)
	}
	return DefaultMaxPayloadSize
}

func (c *wispConnection) handleWispFrame(packet []byte, bufp *[]byte) bool {
	if len(packet) < 5 {
		return false
	}

	packetType := packet[0]
	streamId := binary.LittleEndian.Uint32(packet[1:5])
	payload := packet[5:]

	if c.isV2 && c.handshakeDone != nil {
		select {
		case <-c.handshakeDone:
		default:
			if packetType == packetTypeInfo {
				c.handlePacket(packetType, streamId, payload)
				return false
			}
			if packetType == packetTypeClose && streamId == 0 {
				c.handlePacket(packetType, streamId, payload)
				return false
			}
			return false
		}
	}

	if packetType == packetTypeData {
		return c.handleDataPacket(streamId, payload, bufp)
	}
	c.handlePacket(packetType, streamId, payload)
	return false
}

func maskXOR(b []byte, key [4]byte) {
	maskKey := *(*uint32)(unsafe.Pointer(&key[0]))
	key64 := uint64(maskKey)<<32 | uint64(maskKey)

	for len(b) >= 64 {
		p := unsafe.Pointer(&b[0])
		*(*uint64)(p) ^= key64
		*(*uint64)(unsafe.Add(p, 8)) ^= key64
		*(*uint64)(unsafe.Add(p, 16)) ^= key64
		*(*uint64)(unsafe.Add(p, 24)) ^= key64
		*(*uint64)(unsafe.Add(p, 32)) ^= key64
		*(*uint64)(unsafe.Add(p, 40)) ^= key64
		*(*uint64)(unsafe.Add(p, 48)) ^= key64
		*(*uint64)(unsafe.Add(p, 56)) ^= key64
		b = b[64:]
	}

	for len(b) >= 8 {
		*(*uint64)(unsafe.Pointer(&b[0])) ^= key64
		b = b[8:]
	}

	for i := range b {
		b[i] ^= key[i&3]
	}
}

func (c *wispConnection) sendWSClose(code uint16) {
	buf := make([]byte, 4)
	buf[0] = 0x88
	buf[1] = 2
	binary.BigEndian.PutUint16(buf[2:4], code)
	c.queueWrite(buf)
}
