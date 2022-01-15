package buff

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/free5gc/go-upf/report"
)

func TestServer(t *testing.T) {
	done := make(chan uint16)
	defer close(done)
	addr := "test.unsock"
	qlen := 10
	s, err := OpenServer(addr, qlen)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer os.Remove(addr)

	s.HandleFunc(func(r report.Report) {
		switch r.Type() {
		case report.DLDR:
			r := r.(report.DLDReport)
			done <- r.PDRID
		}
	})

	laddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialUnix("unixgram", nil, laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pkt := []byte{
		0x03, 0x00,
		0x0c, 0x00,
		0xee, 0xbb,
		0xdd, 0xcc,
	}

	_, err = conn.Write(pkt)
	if err != nil {
		t.Fatal(err)
	}
	pdrid := <-done

	if pdrid != 3 {
		t.Errorf("want %v; but got %v\n", 3, pdrid)
	}

	pkt, ok := s.Pop(pdrid)
	if !ok {
		t.Fatal("not found")
	}

	want := []byte{0xee, 0xbb, 0xdd, 0xcc}
	if !bytes.Equal(pkt, want) {
		t.Errorf("want %x; but got %x\n", want, pkt)
	}

	_, ok = s.Pop(pdrid)
	if ok {
		t.Fatal("found")
	}
}
