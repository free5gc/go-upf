package forwarder

import (
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/report"
)

type Empty struct{}

func (Empty) Close() {
}

func (Empty) CreatePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdatePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemovePDR(uint64, *ie.IE) error {
	return nil
}

func (Empty) CreateFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemoveFAR(uint64, *ie.IE) error {
	return nil
}

func (Empty) CreateQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) UpdateQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) RemoveQER(uint64, *ie.IE) error {
	return nil
}

func (Empty) HandleReport(uint64, report.Handler) {
}

func (e Empty) DropReport(uint64) {
}
