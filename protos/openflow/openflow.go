package openflow

import (
	"bytes"
	"encoding/binary"
	//	"fmt"
	"time"

	"github.com/elastic/libbeat/common"
	"github.com/elastic/libbeat/logp"

	"github.com/elastic/packetbeat/config"
	"github.com/elastic/packetbeat/procs"
	"github.com/elastic/packetbeat/protos"
	"github.com/elastic/packetbeat/protos/tcp"
)

type OpenFlowContent interface {
	parse(data []byte)
	fillOutEvent(event *common.MapStr)
}

type OpenFlowMessage struct {
	Ts            time.Time
	NumberOfBulks int64
	Bulks         []string

	TcpTuple     common.TcpTuple
	CmdlineTuple *common.CmdlineTuple
	Direction    uint8

	IsError bool
	Message string
	Size    int

	parseState int
	start      int
	end        int

	version     uint8
	messageType ofp_type
	length      uint16
	transaction uint32

	content OpenFlowContent
}

type OpenFlowTransaction struct {
	Type         string
	tuple        common.TcpTuple
	Src          common.Endpoint
	Dst          common.Endpoint
	ResponseTime int32
	Ts           int64
	JsTs         time.Time
	ts           time.Time
	cmdline      *common.CmdlineTuple
	IsError      bool
	BytesOut     int
	BytesIn      int

	OpenFlow common.MapStr

	message OpenFlowMessage

	timer *time.Timer
}

type OpenFlowStream struct {
	tcptuple *common.TcpTuple

	data []byte

	parseOffset   int
	bytesReceived int

	message *OpenFlowMessage
}

const (
	TransactionsHashSize = 2 ^ 16
	TransactionTimeout   = 10 * 1e9
)

type OpenFlow struct {
	//config
	Ports         []int
	Send_request  bool
	Send_response bool

	transactionsMap map[common.HashableTcpTuple]*OpenFlowTransaction

	results chan common.MapStr
}

func (openflow *OpenFlow) GetPorts() []int {
	return openflow.Ports
}

func (openflow *OpenFlow) Init(test_mode bool, results chan common.MapStr) error {
	openflow.InitDefaults()
	if !test_mode {
		openflow.setFromConfig(config.ConfigSingleton.Protocols.OpenFlow)
	}

	openflow.transactionsMap = make(map[common.HashableTcpTuple]*OpenFlowTransaction, TransactionsHashSize)
	openflow.results = results

	return nil
}

func (openflow *OpenFlow) InitDefaults() {
	openflow.Send_request = false
	openflow.Send_response = false
}

func (openflow *OpenFlow) setFromConfig(config config.OpenFlow) error {

	openflow.Ports = config.Ports

	if config.Send_request != nil {
		openflow.Send_request = *config.Send_request
	}
	if config.Send_response != nil {
		openflow.Send_response = *config.Send_response
	}
	return nil
}

func (openflow *OpenFlow) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	return private, true
}

type OpenFlowPrivateData struct {
	Data [2]*OpenFlowStream
}

func (openFlow *OpenFlow) Parse(pkt *protos.Packet, tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	defer logp.Recover("ParseOpenFlow exception")

	priv := OpenFlowPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(OpenFlowPrivateData)
		if !ok {
			priv = OpenFlowPrivateData{}
		}
	}

	if priv.Data[dir] == nil {
		priv.Data[dir] = &OpenFlowStream{
			tcptuple: tcptuple,
			data:     pkt.Payload,
			message:  &OpenFlowMessage{Ts: pkt.Ts},
		}
	} else {
		// concatenate bytes
		priv.Data[dir].data = append(priv.Data[dir].data, pkt.Payload...)
		if len(priv.Data[dir].data) > tcp.TCP_MAX_DATA_IN_STREAM {
			logp.Debug("openflow", "Stream data too large, dropping TCP stream")
			priv.Data[dir] = nil
			return priv
		}
	}

	stream := priv.Data[dir]
	for len(stream.data) > 0 {
		if stream.message == nil {
			stream.message = &OpenFlowMessage{Ts: pkt.Ts}
		}

		ok, complete := openFlowMessageParser(priv.Data[dir])

		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			priv.Data[dir] = nil
			logp.Debug("openflow", "Ignore OpenFlow message. Drop tcp stream. Try parsing with the next segment")
			return priv
		}

		if complete {

			logp.Err("openflow", "OpenFlow message type: ", stream.message.messageType)

			// all ok, go to next level
			openFlow.handleOpenFlow(stream.message, tcptuple, dir)

			// and reset message
			stream.PrepareForNewMessage()
		} else {
			// wait for more data
			break
		}
	}

	return priv
}

func (openFlow *OpenFlow) handleOpenFlow(m *OpenFlowMessage, tcptuple *common.TcpTuple,
	dir uint8) {

	m.TcpTuple = *tcptuple
	m.Direction = dir
	m.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())

	tuple := m.TcpTuple
	trans := openFlow.transactionsMap[tuple.Hashable()]
	if trans == nil {
		trans = &OpenFlowTransaction{Type: "openflow", tuple: tuple}
		openFlow.transactionsMap[tuple.Hashable()] = trans
	}

	trans.BytesIn = m.Size

	trans.cmdline = m.CmdlineTuple
	trans.ts = m.Ts
	trans.Ts = int64(trans.ts.UnixNano() / 1000) // transactions have microseconds resolution
	trans.JsTs = m.Ts
	trans.Src = common.Endpoint{
		Ip:   m.TcpTuple.Src_ip.String(),
		Port: m.TcpTuple.Src_port,
		Proc: string(m.CmdlineTuple.Src),
	}
	trans.Dst = common.Endpoint{
		Ip:   m.TcpTuple.Dst_ip.String(),
		Port: m.TcpTuple.Dst_port,
		Proc: string(m.CmdlineTuple.Dst),
	}
	if m.Direction == tcp.TcpDirectionReverse {
		trans.Src, trans.Dst = trans.Dst, trans.Src
	}

	trans.OpenFlow = common.MapStr{}

	trans.IsError = m.IsError
	if m.IsError {
		trans.OpenFlow["error"] = m.Message
	} else {
		trans.OpenFlow["return_value"] = m.Message
	}

	trans.BytesOut = m.Size
	trans.message = *m

	trans.ResponseTime = int32(m.Ts.Sub(trans.ts).Nanoseconds() / 1e6) // resp_time in milliseconds

	openFlow.publishTransaction(trans)
}

func (openflow OpenFlowMessage) fillOutEvent(event *common.MapStr) {
	openFlowEvent := common.MapStr{}
	openFlowEvent["version"] = "1.0" //FIXME
	openFlowEvent["type"] = openflow.messageType.String()
	openFlowEvent["transaction_id"] = openflow.transaction

	openflow.content.fillOutEvent(&openFlowEvent)

	(*event)["openflow"] = openFlowEvent
}

func (openFlow *OpenFlow) publishTransaction(t *OpenFlowTransaction) {

	if openFlow.results == nil {
		return
	}

	event := common.MapStr{}
	event["type"] = "openflow"
	if !t.IsError {
		event["status"] = common.OK_STATUS
	} else {
		event["status"] = common.ERROR_STATUS
	}

	event["timestamp"] = common.Time(t.ts)

	t.message.fillOutEvent(&event)

	openFlow.results <- event
}

func (openflow *OpenFlow) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	// TODO: check if we have pending data that we can send up the stack

	return private
}

func openFlowMessageParser(s *OpenFlowStream) (bool, bool) {
	m := s.message
	m.start = s.parseOffset

	if s.parseOffset < len(s.data) {

		if len(s.data) > m.start+8 {
			header := s.data[s.parseOffset : s.parseOffset+8]

			binary.Read(bytes.NewReader(header[0:1]), binary.BigEndian, &m.version)
			binary.Read(bytes.NewReader(header[1:2]), binary.BigEndian, &m.messageType)
			binary.Read(bytes.NewReader(header[2:4]), binary.BigEndian, &m.length)
			binary.Read(bytes.NewReader(header[4:8]), binary.BigEndian, &m.transaction)

			if len(s.data) < m.start+int(m.length) {
				return true, false
			}

			m.content = packetFromType(m.version, m.messageType)
			m.content.parse(s.data[s.parseOffset : s.parseOffset+int(m.length)])
			s.parseOffset += int(m.length)

			return true, true
		}

	}
	return false, false
}

func (stream *OpenFlowStream) PrepareForNewMessage() {
	stream.data = stream.data[stream.parseOffset:]
	stream.parseOffset = 0
	stream.message = &OpenFlowMessage{Ts: stream.message.Ts}
	stream.message.Bulks = []string{}
}

func packetFromType(version uint8, packetType ofp_type) OpenFlowContent {
	logp.Err("openflow", "Found packet type ", packetType)
	if packet, ok := OpenFlowPacketTypes[packetType]; ok {
		return packet
	} else {
		logp.Err("openflow", "Unknown message ", packetType)
		return nil
	}
}
