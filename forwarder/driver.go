package forwarder

import (
	"github.com/wmnsk/go-pfcp/ie"
)

type Driver interface {
	Close()

	CreatePDR(*ie.IE) error
	UpdatePDR(*ie.IE) error
	RemovePDR(*ie.IE) error

	CreateFAR(*ie.IE) error
	UpdateFAR(*ie.IE) error
	RemoveFAR(*ie.IE) error

	CreateQER(*ie.IE) error
	UpdateQER(*ie.IE) error
	RemoveQER(*ie.IE) error
}
