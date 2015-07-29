package openflow

import (
	"fmt"
	"bytes"
	"encoding/binary"

		"github.com/elastic/libbeat/common"
)


var OpenFlowVersion = map[uint8]string{
	0x01: "1.0",
}

var OpenFlowMessageType = map[uint8]string{
	10: "OFPT_PACKET_IN",
}

type OpenFlowPacketIn struct {
	bufferId uint32
	totalLength uint16
  inPort uint16
  reason uint8
}

func (m OpenFlowPacketIn) debug() {
	fmt.Printf("BufferId: %x \n", m.bufferId)
}

func (m *OpenFlowPacketIn) parse(data []byte) {
	binary.Read(bytes.NewReader(data[0:4]), binary.BigEndian, &m.bufferId)
	binary.Read(bytes.NewReader(data[4:6]), binary.BigEndian, &m.totalLength)
	binary.Read(bytes.NewReader(data[6:8]), binary.BigEndian, &m.inPort)
	binary.Read(bytes.NewReader(data[8:9]), binary.BigEndian, &m.reason)
}

func (m OpenFlowPacketIn) fillOutEvent(event *common.MapStr) {

}

type OpenFlowUnImplemented struct {
}

func (m OpenFlowUnImplemented) debug() {
	fmt.Printf("Unimplemented!")
}

func (m *OpenFlowUnImplemented) parse(data []byte) {

}

func (m OpenFlowUnImplemented) fillOutEvent(event *common.MapStr) {

}
