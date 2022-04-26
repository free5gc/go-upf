package report

const (
	DLDR = iota + 1
	USAR
	ERIR
	UPIR
	TMIR
	SESR
	UISR
)

type Report interface {
	Type() int
}

type DLDReport struct {
	PDRID uint16
}

func (r DLDReport) Type() int {
	return DLDR
}

type SessReport struct {
	SEID   uint64
	Report Report
	Action uint16
	BufPkt []byte
}

type BufInfo struct {
	SEID  uint64
	PDRID uint16
}
