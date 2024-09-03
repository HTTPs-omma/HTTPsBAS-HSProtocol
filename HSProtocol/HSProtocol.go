package HSProtocol

import (
	"encoding/binary"
	"fmt"
)

type HS struct {
	ProtocolID   uint8
	HealthStatus uint8
	Command      uint16
	//ProtocolID     uint16
	Identification uint16
	Checksum       uint16
	TotalLength    uint16
	UUID           [16]byte
	Data           []byte
}

type HSProtocolManager struct {
	headerByteSize int
	ProtocolID     uint8
}

func NewHSProtocolManager() *HSProtocolManager {
	return &HSProtocolManager{
		headerByteSize: 24,
		ProtocolID:     1,
	}
}

func (hs *HSProtocolManager) Parsing(data []byte) (*HS, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("Not enough data to parse the HS protocol")
	}

	commandHeader := binary.BigEndian.Uint16(data[:2])
	command := commandHeader & 0b1111111111
	healthStatus := uint8((commandHeader >> 10) & 0b11)
	ProtocolID := uint8((commandHeader >> 12) & 0b1111)

	totalLength := binary.BigEndian.Uint16(data[6:8])

	heap_data := make([]byte, int(totalLength)-hs.headerByteSize)
	copy(heap_data, data[24:])

	packet := &HS{
		ProtocolID:     ProtocolID,
		HealthStatus:   healthStatus,
		Command:        command,
		Identification: binary.BigEndian.Uint16(data[2:4]),
		Checksum:       binary.BigEndian.Uint16(data[4:6]),
		TotalLength:    totalLength,
		Data:           heap_data,
	}

	copy(packet.UUID[:], data[8:24])

	return packet, nil
}

func (hs *HSProtocolManager) ValidateCheckSum(data []byte) bool {
	var checksum []byte = hs.GetCheckSum(data)

	if (checksum[0] == data[4]) && (checksum[1] == data[5]) {
		return true
	} else {
		return false
	}
}

func (hs *HSProtocolManager) GetCheckSum(data []byte) []byte {
	var checksum uint32 = 0
	for i := 0; i < hs.headerByteSize; i += 2 {
		if i >= 4 && i < 6 {
			continue
		}
		checksum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		if checksum > 0xffff {
			checksum += (checksum >> 16)
		}
	}
	checksum = ^checksum

	bchecksum := make([]byte, 2)
	binary.BigEndian.PutUint16(bchecksum, uint16(checksum))

	return bchecksum
}

func (hsmgr *HSProtocolManager) ToBytes(hs *HS) ([]byte, error) {
	hs.TotalLength = uint16(hsmgr.headerByteSize + len(hs.Data))

	buf := make([]byte, hs.TotalLength)

	var commandHeader uint16
	commandHeader |= uint16(hs.ProtocolID) << 12
	commandHeader |= uint16(hs.HealthStatus) << 10
	commandHeader |= uint16(hs.Command)

	binary.BigEndian.PutUint16(buf[0:2], commandHeader)     // ProtocolID, HealthStatus, Command
	binary.BigEndian.PutUint16(buf[2:4], hs.Identification) // Identification
	binary.BigEndian.PutUint16(buf[6:8], hs.TotalLength)    // TotalLength
	copy(buf[8:24], hs.UUID[:])                             // UUID
	copy(buf[24:], hs.Data)                                 // Data
	copy(buf[4:6], hsmgr.GetCheckSum(buf))                  // Checksum 계산

	return buf, nil
}

func (hs *HSProtocolManager) PrintByte(data []byte) {
	for i := 0; i < len(data); i++ {
		fmt.Printf("0x%02X ", data[i])
	}
}
