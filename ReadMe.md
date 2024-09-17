
---

# HS Protocol Library

**작성자:** 허남정 연구원  
**Release 정보:**

| Release Date | Commit                                   | 작성자 |
|--------------|------------------------------------------|--------|
| 2024.08.30   | APT 시뮬레이터와 Managing Server 간의 통신 라이브러리 | 허남정 |

---

## Example: HS Protocol

### Example 1: 데이터 파싱

만약 패킷이 아래와 같이 주어진다면:

```go
packetData := []byte{
    0x41, 0x55, // ProtocolID: 4 (0100), HealthStatus: 1 (01), Command: 341 (0101010101)
    0x12, 0x34, // Identification: 0x1234
    0xb8, 0xa2, // Checksum: 0x4112
    0x00, 0x1C, // TotalLength: 001C : 28
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // UUID part 1
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // UUID part 2
    0xAA, 0xBC, 0xCC, 0xDD, 0xFF, // Data start
}
```

이 데이터를 파싱하는 예제 코드는 다음과 같습니다:

```go
hsManager := HSProtocol.NewHSProtocolManager()

hs, err := hsManager.Parsing(packetData)
if err != nil {
    log.Fatalf("Failed to parse HS packet: %v", err)
}

fmt.Printf("ProtocolID: %d\n", hs.ProtocolID)
fmt.Printf("Health Status: %d\n", hs.HealthStatus)
fmt.Printf("Command: %d\n", hs.Command)
fmt.Printf("Identification: %d\n", hs.Identification)
fmt.Printf("Checksum: %x\n", hs.Checksum)
fmt.Printf("Total Length: %d\n", hs.TotalLength)
fmt.Printf("UUID: %x\n", hs.UUID)
fmt.Printf("Data: %x\n", hs.Data)
```

**출력:**

```shell
ProtocolID: 4
Health Status: 1
Command: 341
Identification: 4660
Checksum: b8a2
Total Length: 28
UUID: 123456789abcdef01122334455667788
Data: aabcccddff
```

### Example 2: 데이터 유효성 검사 (Checksum)

Checksum 계산 방법으로 IPv4 알고리즘을 사용했습니다.
1. 헤더를 2Byte 단위로 나눠서 더합니다.
2. 덧셈 결과가 2Byte를 초과하면 올림수(Carry)를 하위 비트에 더합니다. (예: 2DE46 -> DE46 + 0002 = DE48)
3. 덧셈 결과에 1의 보수를 취합니다.

**코드:**

```go
fmt.Printf("validate : %b \n", hsManager.ValidateCheckSum(packetData))
fmt.Printf("validate : %x \n", hsManager.GetCheckSum(packetData))
```

**출력:**

```shell
validate : true 
validate : b8a2
```

### Example 3: toByte (직렬화)

**코드:**

```go
data2, err := hsManager.ToBytes(hs)
hs2, err := hsManager.Parsing(data2)
hsManager.PrintByte(data2)
```

**출력:**

```shell
0x41 0x55 0x12 0x34 0xB8 0xA2 0x00 0x1C 0x12 0x34 0x56 0x78 0x9A 0xBC 0xDE 0xF0 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0xAA 0xBC 0xCC 0xDD 0xFF
```

## Reference
### Health Status (HS) field
| HS field | status | 설명                |
|----------|--------|-------------------|
| **0b00**   | NEW    | Agent가 대기중인 상태    |
| **0b01**     | RUN    | Agent 가 동작중인 상태   
| **0b10**     | STOP   | Agent 가 잠시 중단된 상태 |
| **0b11**     | DELETED | Agent 가 삭제된 상태    | 



### Command: 0 (0b0000000000)
- **제목:** Ack
- **설명:** Identification에 대응되는 패킷을 잘 처리했음을 알림.

### Command: 1 (0b0000000001)
- **제목:** updateAgentProtocol
- **설명:** Agent가 자신의 통신 프로토콜에 대한 설정 값을 ProtocolID 필드에 담아 전달합니다.

| Code   | 통신 프로토콜 | 보기       |
  |--------|---------|----------|
| 0b0001 | TCP     |          |
| 0b0010 | UDP     | -------- |
| 0b0011 | HTTP    | -------- |
| 0b0100 | HTTPS   | -------- |

### Command: 2 (0b0000000010)
- **제목:** updateAgentStatus
- **설명:** Agent가 자신의 통신 방법을 전달합니다.
    - 0b00: stopping
    - 0b01: waiting (새로 생성)
    - 0b10: running
    - 0b11: remove (삭제 요청)

### Command: 3 (0b0000000011)
- **제목:** sendAgentSysInfo 데이터
- **설명:** Agent가 컴퓨터의 정보를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.

### Command: 4 (0b0000000100)
- **제목:** ERROR ACK
- **설명:** Server 측에서 요청된 명령 수행에 에러 응답을 함. 

### Command: 5 (0b0000000101)
- **제목:** sendAgentSysAppInfo 데이터
- **설명:** Agent가 ApplicationInfo 정보를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.

### Command: 6 (0b0000000110)
- **제목:** fetchInstruction
- **설명:** Agent가 Server 측에 공격 시나리오 (YAML 파일)를 요청합니다. 이때 데이터는 Data 필드에 YAML 형태로 직렬화하여 전송됩니다.

### Command: 7 (0b0000000111)
- **제목:** sendProcedureLog
- **설명:** Agent가 Server 측에 공격 시나리오 로그를 JSON 형태로 Data 필드에 직렬화하여 전송합니다.

---

## 잡생각
- 각 필드를 4bit 단위로 쪼개는 것이 더 편할 것 같습니다.
- Command를 0x0001로 표현했으면 읽기 쉬웠을 텐데, 애매하게 10bit로 표현해서 가독성이 떨어졌습니다.

---