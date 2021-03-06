package report

type ReportType int

const (
	DLDR ReportType = iota + 1
	USAR
	ERIR
	UPIR
	TMIR
	SESR
	UISR
)

func (t ReportType) String() string {
	str := []string{"", "DLDR", "USAR", "ERIR", "UPIR", "TMIR", "SESR", "UISR"}
	return str[t]
}

type Report interface {
	Type() ReportType
}

type DLDReport struct {
	PDRID uint16
}

func (r DLDReport) Type() ReportType {
	return DLDR
}

type USAReport struct {
	URRID       uint32
	URSEQN      uint32
	USARTrigger UsageReportTrigger
}

type UsageReportTrigger struct {
	PERIO uint8
	VOLTH uint8
	TIMTH uint8
	QUHTI uint8
	START uint8
	STOPT uint8
	DROTH uint8
	IMMER uint8
	VOLQU uint8
	TIMQU uint8
	LIUSA uint8
	TERMR uint8
	MONIT uint8
	ENVCL uint8
	MACAR uint8
	EVETH uint8
	EVEQU uint8
	TEBUR uint8
	IPMJL uint8
	QUVTI uint8
	EMRRE uint8
}

func (r USAReport) Type() ReportType {
	return USAR
}

const (
	DROP = 1 << 0
	FORW = 1 << 1
	BUFF = 1 << 2
	NOCP = 1 << 3
)

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
