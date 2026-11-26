package pfcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

func pdrReferenceTestPDI() *ie.IE {
	return ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess))
}

func TestParseCreatePDRTracksFARAndQERReferences(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1010),
		ie.NewPrecedence(255),
		pdrReferenceTestPDI(),
		ie.NewFARID(10),
		ie.NewQERID(1010),
		ie.NewURRID(5),
	)

	pdr, err := parseCreatePDR(req)
	require.NoError(t, err)
	require.NotNil(t, pdr.FARID)
	assert.Equal(t, uint32(10), *pdr.FARID)
	assert.Equal(t, []uint32{1010}, pdr.QERIDs)
	assert.Equal(t, []uint32{5}, pdr.URRIDs)
}

// An absent FAR ID IE leaves FARID nil, distinct from a reference to FAR 0.
func TestParseCreatePDRNoFARIDReferenced(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		pdrReferenceTestPDI(),
	)

	pdr, err := parseCreatePDR(req)
	require.NoError(t, err)
	require.Nil(t, pdr.FARID)
	assert.Empty(t, pdr.QERIDs)
}

// Preserve every QER reference in a PDR.
func TestParseCreatePDRMultipleQERIDs(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		pdrReferenceTestPDI(),
		ie.NewFARID(2),
		ie.NewQERID(10),
		ie.NewQERID(11),
	)

	pdr, err := parseCreatePDR(req)
	require.NoError(t, err)
	assert.Equal(t, []uint32{10, 11}, pdr.QERIDs)
}

func TestParseUpdatePDRTracksFARAndQERReferences(t *testing.T) {
	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewFARID(4),
		ie.NewQERID(7),
	)

	pdr, err := parseUpdatePDR(req)
	require.NoError(t, err)
	require.NotNil(t, pdr.FARID)
	assert.Equal(t, uint32(4), *pdr.FARID)
	assert.Equal(t, []uint32{7}, pdr.QERIDs)
}

func TestParseUpdatePDRNoFARIDReferenced(t *testing.T) {
	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
	)

	pdr, err := parseUpdatePDR(req)
	require.NoError(t, err)
	require.Nil(t, pdr.FARID)
	assert.Empty(t, pdr.QERIDs)
}
