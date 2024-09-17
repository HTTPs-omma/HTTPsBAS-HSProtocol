package HSProtocol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func ByteArrayToHexString(b [16]byte) string {
	return hex.EncodeToString(b[:])
}

// 16진수 문자열을 [16]byte로 변환
func HexStringToByteArray(s string) ([16]byte, error) {
	var byteArray [16]byte
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return byteArray, err
	}
	copy(byteArray[:], bytes)
	return byteArray, nil
}

const (
	NEW     = 0b00
	WAIT    = 0b01
	RUN     = 0b10
	DELETED = 0b11
)

const (
	TCP   = 0b0001
	UDP   = 0b0010
	HTTP  = 0b0011
	HTTPS = 0b0100
)

const (
	ACK = 0b0000000000 // Command: 0 (0b0000000000)
	// 제목: Ack
	// 설명: Identification에 대응되는 패킷을 잘 처리했음을 알림.

	UPDATE_AGENT_PROTOCOL = 0b0000000001 // Command: 1 (0b0000000001)
	// 제목: updateAgentProtocol
	// 설명: Agent가 자신의 통신 프로토콜에 대한 설정 값을 ProtocolID 필드에 담아 전달합니다.
	// Code   | 통신 프로토콜 | 보기
	// 0b0001 | TCP
	// 0b0010 | UDP     --------
	// 0b0011 | HTTP    --------
	// 0b0100 | HTTPS   --------

	UPDATE_AGENT_STATUS = 0b0000000010 // Command: 2 (0b0000000010)
	// 제목: updateAgentStatus
	// 설명: Agent가 자신의 통신 방법을 전달합니다.
	// 0b00: stopping
	// 0b01: waiting (새로 생성)
	// 0b10: running
	// 0b11: remove  (삭제 요청)

	SEND_AGENT_SYS_INFO = 0b0000000011 // Command: 3 (0b0000000011)
	// 제목: sendAgentSysInfo
	// 설명: Agent가 컴퓨터의 정보를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.

	ERROR_ACK = 0b0000000100 // Command: 4 (0b0000000100)
	// 제목: 예약
	// 설명: 예약

	SEND_AGENT_APP_INFO = 0b0000000101 // Command: 5 (0b0000000101)
	// 제목: sendAgentSysAppInfo
	// 설명: Agent가 ApplicationInfo 정보를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.

	FETCH_INSTRUCTION = 0b0000000110 // Command: 6 (0b0000000110)
	// 제목: fetchInstruction
	// 설명: Agent가 Server 측에 공격 시나리오 (YAML 파일)를 요청합니다. 이때 데이터는 Data 필드에 YAML 형태로 직렬화하여 전송됩니다.

	SEND_PROCEDURE_LOG = 0b0000000111 // Command: 7 (0b0000000111)
	// 제목: sendProcedureLog
	// 설명: Agent가 Server 측에 공격 시나리오 로그를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.
)

// Command 상수를 정의
type HS struct {
	ProtocolID     uint8
	HealthStatus   uint8
	Command        uint16
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
