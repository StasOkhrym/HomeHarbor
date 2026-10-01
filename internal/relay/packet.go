package relay

import "errors"

const (
	maxIdentifierLength = 128
	maxPacketPayload    = 64 << 10
)

type Packet struct {
	SessionID           string
	SourceDeviceID      string
	DestinationDeviceID string
	Payload             []byte
}

func EncodePacket(packet Packet) ([]byte, error) {
	if len(packet.Payload) == 0 || len(packet.Payload) > maxPacketPayload {
		return nil, errors.New("invalid relay packet payload size")
	}
	ids := []string{packet.SessionID, packet.SourceDeviceID, packet.DestinationDeviceID}
	size := 3 + len(packet.Payload)
	for _, id := range ids {
		if len(id) == 0 || len(id) > maxIdentifierLength {
			return nil, errors.New("invalid relay packet identifier")
		}
		size += len(id)
	}
	out := make([]byte, size)
	offset := 0
	for _, id := range ids {
		out[offset] = byte(len(id))
		offset++
		copy(out[offset:], id)
		offset += len(id)
	}
	copy(out[offset:], packet.Payload)
	return out, nil
}

func DecodePacket(data []byte) (Packet, error) {
	var values [3]string
	offset := 0
	for index := range values {
		if offset >= len(data) {
			return Packet{}, errors.New("truncated relay packet")
		}
		length := int(data[offset])
		offset++
		if length == 0 || length > maxIdentifierLength || offset+length > len(data) {
			return Packet{}, errors.New("invalid relay packet identifier")
		}
		values[index] = string(data[offset : offset+length])
		offset += length
	}
	if offset >= len(data) {
		return Packet{}, errors.New("empty relay payload")
	}
	if len(data)-offset > maxPacketPayload {
		return Packet{}, errors.New("relay packet payload too large")
	}
	return Packet{
		SessionID:           values[0],
		SourceDeviceID:      values[1],
		DestinationDeviceID: values[2],
		Payload:             data[offset:],
	}, nil
}
