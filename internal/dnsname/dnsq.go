package dnsname

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// QueryA asks a DNS server directly (UDP) for the A records of domain. The
// packet is built by hand: one question, recursion desired. A NXDOMAIN or an
// empty answer gives an empty list and no error.
func QueryA(ctx context.Context, server, domain string, timeout time.Duration) ([]netip.Addr, error) {
	id := make([]byte, 2)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	q, err := buildQuery(binary.BigEndian.Uint16(id), domain)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dl := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = conn.SetDeadline(dl)
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("DNS-сервер не ответил: %w", err)
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == binary.BigEndian.Uint16(id) {
			return parseA(buf[:n])
		}
	}
}

func buildQuery(id uint16, domain string) ([]byte, error) {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // QDCOUNT
	for _, l := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if l == "" || len(l) > 63 {
			return nil, errors.New("некорректное DNS-имя")
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1) // root, QTYPE A, QCLASS IN
	return b, nil
}

// skipName returns the offset after the (possibly compressed) name at off.
func skipName(m []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(m) {
			return 0, errors.New("обрезанный ответ DNS")
		}
		c := int(m[off])
		switch {
		case c == 0:
			return off + 1, nil
		case c&0xC0 == 0xC0:
			if off+2 > len(m) {
				return 0, errors.New("обрезанный ответ DNS")
			}
			return off + 2, nil
		case c&0xC0 != 0:
			return 0, errors.New("некорректный ответ DNS")
		default:
			off += 1 + c
		}
	}
	return 0, errors.New("некорректный ответ DNS")
}

func parseA(m []byte) ([]netip.Addr, error) {
	if len(m) < 12 {
		return nil, errors.New("обрезанный ответ DNS")
	}
	if m[2]&0x80 == 0 {
		return nil, errors.New("это не ответ DNS")
	}
	if rc := m[3] & 0x0F; rc != 0 && rc != 3 {
		return nil, fmt.Errorf("DNS-сервер ответил ошибкой (код %d)", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(m, off); err != nil {
			return nil, err
		}
		off += 4
	}
	out := []netip.Addr{}
	for i := 0; i < an; i++ {
		if off, err = skipName(m, off); err != nil {
			return nil, err
		}
		if off+10 > len(m) {
			return nil, errors.New("обрезанный ответ DNS")
		}
		typ, rdlen := binary.BigEndian.Uint16(m[off:]), int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return nil, errors.New("обрезанный ответ DNS")
		}
		if typ == 1 && rdlen == 4 {
			out = append(out, netip.AddrFrom4([4]byte(m[off:off+4])))
		}
		off += rdlen
	}
	return out, nil
}
