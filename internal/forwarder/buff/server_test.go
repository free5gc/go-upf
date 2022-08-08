package buff

import (
	"bytes"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/free5gc/go-upf/internal/report"
)

type testHandler struct {
	q map[uint64]map[uint16]chan []byte
}

func NewTestHandler() *testHandler {
	return &testHandler{q: make(map[uint64]map[uint16]chan []byte)}
}

func (h *testHandler) Close() {
	for _, s := range h.q {
		for _, q := range s {
			close(q)
		}
	}
}

func (h *testHandler) NotifySessReport(sr report.SessReport) {
	s, ok := h.q[sr.SEID]
	if !ok {
		return
	}
	for _, rep := range sr.Reports {
		switch r := rep.(type) {
		case report.DLDReport:
			if r.Action&report.BUFF != 0 && len(r.BufPkt) > 0 {
				q, ok := s[r.PDRID]
				if !ok {
					qlen := 10
					s[r.PDRID] = make(chan []byte, qlen)
					q = s[r.PDRID]
				}
				q <- r.BufPkt
			}
		default:
		}
	}
}

func (h *testHandler) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	s, ok := h.q[seid]
	if !ok {
		return nil, false
	}
	q, ok := s[pdrid]
	if !ok {
		return nil, false
	}
	select {
	case pkt := <-q:
		return pkt, true
	default:
		return nil, false
	}
}

func TestServer(t *testing.T) {
	addr := "test.unsock"
	var wg sync.WaitGroup
	s, err := OpenServer(&wg, addr)
	if err != nil {
		t.Fatal(err)
	}
	h := NewTestHandler()
	defer func() {
		h.Close()
		s.Close()
		wg.Wait()
	}()
	defer func() {
		err = os.Remove(addr)
		if err != nil {
			t.Log(err)
		}
	}()

	seid := uint64(6)
	h.q[seid] = make(map[uint16]chan []byte)
	s.Handle(h)

	laddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialUnix("unixgram", nil, laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			t.Log(err)
		}
	}()

	pkt := []byte{
		0x06, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x00,
		0x0c, 0x00,
		0xee, 0xbb,
		0xdd, 0xcc,
	}

	N := 10
	for i := 0; i < N; i++ {
		_, err = conn.Write(pkt)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)

		pdrid := uint16(3)
		pkt, ok := s.Pop(seid, pdrid)
		if !ok {
			t.Fatal("not found")
		}

		want := []byte{0xee, 0xbb, 0xdd, 0xcc}
		if !bytes.Equal(pkt, want) {
			t.Errorf("want %x; but got %x\n", want, pkt)
		}

		_, ok = s.Pop(seid, pdrid)
		if ok {
			t.Fatal("found")
		}
	}
}
