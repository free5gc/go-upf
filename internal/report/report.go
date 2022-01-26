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
