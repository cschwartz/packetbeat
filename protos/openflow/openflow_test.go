package openflow

import "testing"

func TestOpenFlowParser_PacketIn(t *testing.T) {
	message := []byte("\x01" + // Version 1
		"\x0a" + // OFPT_PACKET_IN
		"\x00\x67" + // Length 103
		"\x00\x00\x00\x00" + // Transaction 0
		"\xff\xff\xff\xff" + // Buffer Id 0xffffffff
		"\x00\x55" + // Total length 85
		"\x00\x19" + // In port 25
		"\x01" + // Reason 1
		"\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00") // Padding 0
	// 85 bytes payload

	stream := &OpenFlowStream{data: message, message: new(OpenFlowMessage)}

	ok, complete := openFlowMessageParser(stream)

	if !ok {
		t.Errorf("Parsing returned error")
	}
	if !complete {
		t.Errorf("Expecting a complete message")
	}

	if stream.message.version != 0x01 {
		t.Errorf("Invalid version '%s', expected '1.0'", stream.message.version)
	}

	if stream.message.messageType != 10 {
		t.Errorf("Invalid packet type '%s', expected 'OFPT_PACKET_IN'", stream.message.messageType)
	}

	if stream.message.length != 103 {
		t.Errorf("Invalid length '%d', expected '103'", stream.message.length)
	}

	if stream.message.transaction != 0 {
		t.Errorf("Invalid length '%d', expected '0'", stream.message.transaction)
	}

	stream.message.content.debug()
	packetIn, ok := stream.message.content.(*OpenFlowPacketIn)
	if !ok {
	 	t.Errorf("Invalid type")
	}

	if packetIn.bufferId != 0xffffffff {
	 	t.Errorf("Invalid buffer id '%d', expected '0xffffffff'", packetIn.bufferId)
	}

	if packetIn.totalLength != 85 {
		t.Errorf("Invalid totalLength '%d', expected '85'", packetIn.totalLength)
	}

	if packetIn.inPort != 25 {
		t.Errorf("Invalid inPort '%d', expected '25'", packetIn.inPort)
	}

	if packetIn.reason != 1 {
		t.Errorf("Invalid reason '%d', expected '1'", packetIn.reason)
	}
}
