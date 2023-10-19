package sniffer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"github.com/Dreamacro/clash/common/buf"
	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/metacubex/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
	"io"
	"sync"
	"time"
)

// Modified from https://github.com/v2fly/v2ray-core/blob/master/common/protocol/quic/sniff.go

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1
	// RFC9000 7.5. Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames.
	quicCryptoSize = 4096
)

var (
	quicSaltOld       = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt          = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	errNotQuic        = errors.New("not QUIC")
	errNotQuicInitial = errors.New("not QUIC initial packet")
)

type QuicSniffer struct {
	*BaseSniffer

	conn     map[string]*quicConnection
	connLock sync.RWMutex
}

func NewQuicSniffer(snifferConfig SnifferConfig) (*QuicSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](443, 443)}
	}
	return &QuicSniffer{
		conn:        make(map[string]*quicConnection),
		BaseSniffer: NewBaseSniffer(ports, C.UDP),
	}, nil
}

func (sniffer *QuicSniffer) Protocol() string {
	return "quic"
}

func (sniffer *QuicSniffer) SupportNetwork() C.NetWork {
	return C.UDP
}

func (sniffer *QuicSniffer) SniffData(b []byte) (string, error) {
	data, err := sniffer.readQuicData(b)
	if err != nil {
		return "", err
	}

	<-data.done

	sniffer.connLock.Lock()
	delete(sniffer.conn, string(data.id))
	sniffer.connLock.Unlock()

	data.lock.RLock()
	defer data.lock.RUnlock()
	if data.ret != nil {
		return *data.ret, nil
	}

	return "", errNotQuic
}

func (sniffer *QuicSniffer) getOrCreateConn(id []byte) *quicConnection {
	sniffer.connLock.RLock()
	if conn, ok := sniffer.conn[string(id)]; ok {
		defer sniffer.connLock.RUnlock()
		return conn
	}
	sniffer.connLock.RUnlock()

	sniffer.connLock.Lock()
	conn := newQuicConnection(id)
	sniffer.conn[string(id)] = conn
	sniffer.connLock.Unlock()

	go func() {
		<-time.After(time.Second)
		conn.close()
	}()

	return conn
}

func (sniffer *QuicSniffer) readQuicData(b []byte) (*quicConnection, error) {
	buffer := buf.As(b)
	typeByte, err := buffer.ReadByte()
	if err != nil {
		return nil, errNotQuic
	}
	isLongHeader := typeByte&0x80 > 0
	if !isLongHeader || typeByte&0x40 == 0 {
		return nil, errNotQuicInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return nil, errNotQuic
	}

	versionNumber := binary.BigEndian.Uint32(vb)

	if versionNumber != 0 && typeByte&0x40 == 0 {
		return nil, errNotQuic
	} else if versionNumber != versionDraft29 && versionNumber != version1 {
		return nil, errNotQuic
	}

	var destConnID []byte
	if l, err := buffer.ReadByte(); err != nil {
		return nil, errNotQuic
	} else if destConnID, err = buffer.ReadBytes(int(l)); err != nil {
		return nil, errNotQuic
	}

	conn := sniffer.getOrCreateConn(destConnID)

	if (typeByte&0x30)>>4 != 0x0 {
		conn.close()
		return nil, errNotQuicInitial
	}

	if l, err := buffer.ReadByte(); err != nil {
		return nil, errNotQuic
	} else if _, err := buffer.ReadBytes(int(l)); err != nil {
		return nil, errNotQuic
	}

	tokenLen, err := quicvarint.Read(buffer)
	if err != nil || tokenLen > uint64(len(b)) {
		return nil, errNotQuic
	}

	if _, err = buffer.ReadBytes(int(tokenLen)); err != nil {
		return nil, errNotQuic
	}

	packetLen, err := quicvarint.Read(buffer)
	if err != nil {
		return nil, errNotQuic
	}

	hdrLen := len(b) - buffer.Len()

	var salt []byte
	if versionNumber == version1 {
		salt = quicSalt
	} else {
		salt = quicSaltOld
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
	secret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	hpKey := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}

	cache := buf.NewPacket()
	defer cache.Release()

	mask := cache.Extend(block.BlockSize())
	block.Encrypt(mask, b[hdrLen+4:hdrLen+4+16])
	firstByte := b[0]
	// Encrypt/decrypt first byte.

	if isLongHeader {
		// Long header: 4 bits masked
		// High 4 bits are not protected.
		firstByte ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		// High 3 bits are not protected.
		firstByte ^= mask[0] & 0x1f
	}
	packetNumberLength := int(firstByte&0x3 + 1) // max = 4 (64-bit sequence number)
	extHdrLen := hdrLen + packetNumberLength

	// copy to avoid modify origin data
	extHdr := cache.Extend(extHdrLen)
	copy(extHdr, b)
	extHdr[0] = firstByte

	packetNumber := extHdr[hdrLen:extHdrLen]
	// Encrypt/decrypt packet number.
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}

	data := b[extHdrLen : int(packetLen)+hdrLen]

	key := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	// We only decrypt once, so we do not need to XOR it back.
	// https://github.com/quic-go/qtls-go1-20/blob/e132a0e6cb45e20ac0b705454849a11d09ba5a54/cipher_suites.go#L496
	for i, b := range packetNumber {
		iv[len(iv)-len(packetNumber)+i] ^= b
	}
	dst := cache.Extend(len(data))
	decrypted, err := aead.Open(dst[:0], iv, data, extHdr)
	if err != nil {
		return nil, err
	}

	buffer = buf.As(decrypted)

	for i := 0; !buffer.IsEmpty(); i++ {
		frameType := byte(0x0) // Default to PADDING frame
		for frameType == 0x0 && !buffer.IsEmpty() {
			frameType, _ = buffer.ReadByte()
		}
		switch frameType {
		case 0x00: // PADDING frame
		case 0x01: // PING frame
		case 0x02, 0x03: // ACK frame
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Largest Acknowledged
				return nil, io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Delay
				return nil, io.ErrUnexpectedEOF
			}
			ackRangeCount, err := quicvarint.Read(buffer) // Field: ACK Range Count
			if err != nil {
				return nil, io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: First ACK Range
				return nil, io.ErrUnexpectedEOF
			}
			for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> Gap
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> ACK Range Length
					return nil, io.ErrUnexpectedEOF
				}
			}
			if frameType == 0x03 {
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
					return nil, io.ErrUnexpectedEOF
				}
			}
		case 0x06: // CRYPTO frame, we will use this frame
			offset, err := quicvarint.Read(buffer) // Field: Offset
			if err != nil {
				return nil, io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Length
			if err != nil || length > uint64(buffer.Len()) {
				return nil, io.ErrUnexpectedEOF
			}

			conn.lock.Lock()
			if conn.dataLength < uint(offset+length) {
				conn.dataLength = uint(offset + length)
			}

			if _, err := buffer.Read(conn.buffer[offset : offset+length]); err != nil { // Field: Crypto Data
				conn.lock.Unlock()
				return nil, io.ErrUnexpectedEOF
			}
			conn.lock.Unlock()
		case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Error Code
				return nil, io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Frame Type
				return nil, io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Reason Phrase Length
			if err != nil {
				return nil, io.ErrUnexpectedEOF
			}
			if _, err := buffer.ReadBytes(int(length)); err != nil { // Field: Reason Phrase
				return nil, io.ErrUnexpectedEOF
			}
		default:
			// Only above frame types are permitted in initial packet.
			// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
			return nil, errNotQuicInitial
		}
	}

	_ = conn.TryAssemble()

	return conn, nil
}

func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
