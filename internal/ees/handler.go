package ees

import (
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/report"
)

// Handler implements report.Handler for the EES module.
// It receives unsolicited usage reports from the kernel (via Dispatcher)
// and forwards them to the Aggregator (or processes them directly).
type Handler struct {
	aggregator *Aggregator
	logger     *logrus.Entry
}

func NewHandler(aggregator *Aggregator, logger *logrus.Entry) *Handler {
	return &Handler{
		aggregator: aggregator,
		logger:     logger,
	}
}

// NotifySessReport is called when the Forwarder pushes a report (e.g., periodic URR).
func (h *Handler) NotifySessReport(sessRpt report.SessReport) {
	h.logger.Infof("EES Handler received report from dispatcher (SEID: %d, ReportCount: %d)",
		sessRpt.SEID, len(sessRpt.Reports))

	// Filter: Check if these reports belong to EES (URR ID based or blind forwarding?)
	// For MVP, we pass it to Aggregator.PushReport
	h.aggregator.PushReport(sessRpt)
}

// PopBufPkt is not supported by EES.
func (h *Handler) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	return nil, false
}
