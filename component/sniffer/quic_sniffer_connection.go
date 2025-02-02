package sniffer

import (
	"sync"
)

type quicConnection struct {
	lock       sync.RWMutex
	buffer     []byte
	dataLength uint
	// callback for connection done
	done   chan struct{}
	closed bool

	ret *string
	id  []byte
}

func newQuicConnection(id []byte) *quicConnection {
	return &quicConnection{
		buffer:     make([]byte, quicCryptoSize),
		dataLength: 0,
		done:       make(chan struct{}),
		id:         id,
	}
}

func (conn *quicConnection) TryAssemble() error {
	conn.lock.RLock()
	domain, err := ReadClientHello(conn.buffer[:conn.dataLength])
	conn.lock.RUnlock()
	if err != nil {
		return err
	}

	conn.lock.Lock()
	conn.ret = domain
	conn.lock.Unlock()
	conn.close()

	return err
}

func (conn *quicConnection) close() {
	conn.lock.Lock()
	if !conn.closed {
		close(conn.done)
		conn.closed = true
	}
	conn.lock.Unlock()
}
