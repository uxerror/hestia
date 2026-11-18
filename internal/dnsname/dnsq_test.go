package dnsname

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestQueryAAgainstFakeServer(t *testing.T) {
	ag := &fakeAG{}
	ag.list = nil
	ag.set("hestia.home", "10.10.10.5")
	ag.set("two.home", "10.10.10.6")
	ag.set("two.home", "10.10.10.7")
	d := newFakeDNS(t, ag)
	server := d.conn.LocalAddr().String()

	got, err := QueryA(context.Background(), server, "Hestia.Home.", time.Second)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("10.10.10.5") {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := QueryA(context.Background(), server, "two.home", time.Second); err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	// NXDOMAIN is an empty answer, not an error.
	if got, err := QueryA(context.Background(), server, "none.home", time.Second); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := QueryA(context.Background(), server, "a..b", time.Second); err == nil {
		t.Fatal("bad name")
	}
	// A server that never answers times out.
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	start := time.Now()
	if _, err := QueryA(context.Background(), silent.LocalAddr().String(), "x.home", 100*time.Millisecond); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("%v", err)
	}
}

func TestParseARejectsGarbage(t *testing.T) {
	q, _ := buildQuery(7, "a.home")
	ok := append([]byte(nil), q...)
	ok[2], ok[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(ok[6:], 1)
	ok = append(ok, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 10, 10, 1)
	if got, err := parseA(ok); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	for name, m := range map[string][]byte{
		"short":       ok[:5],
		"not a reply": q,
		"truncated":   ok[:len(ok)-2],
		"servfail":    append([]byte{0, 7, 0x81, 0x82}, ok[4:]...),
	} {
		if _, err := parseA(m); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A compression loop does not hang.
	loop := append([]byte(nil), ok[:12]...)
	loop[7] = 1
	loop = append(loop, 0xC0, 12)
	if _, err := parseA(loop); err != nil {
		_ = err // an error is fine, a hang is not
	}
}
