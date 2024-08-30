## HS Protocol Library


작성자 : 허남정 연구원

Release 정보 :


| Release Date | Commit                                 | 작성자 |
|--------------|----------------------------------------| ------ |
| 2024.08.30   | APT 시뮬레이터와 Mananging Sever 간의 통신 라이브러리 | 허남정   |
|              |                                        |        |


## Example. HS Protocol

---
 
Example. 만약 패킷이 다음과 같이 받는다면,

```go
packetData := []byte{
    0x41, 0x55, // Version: 4 (0100), HealthStatus: 1 (01), Command: 341 (0101010101)
    0x12, 0x34, // Identification: 0x1234
    0xb8, 0xa2, // Checksum: 0x4112
    0x00, 0x1C, // TotalLength: 001C : 28
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // UUID part 1
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // UUID part 2
    0xAA, 0xBC, 0xCC, 0xDD, 0xFF, // Data start
}
```

### Example.1 데이터 파싱

코드 : 
```go
	hsManager := HSProtocol.NewHSProtocolManager()
	
	hs, err := hsManager.Parsing(packetData)
	if err != nil {
		log.Fatalf("Failed to parse HS packet: %v", err)
	}

	fmt.Printf("Version: %d\n", hs.Version)
	fmt.Printf("Health Status: %d\n", hs.HealthStatus)
	fmt.Printf("Command: %d\n", hs.Command)
	fmt.Printf("Identification: %d\n", hs.Identification)
	fmt.Printf("Checksum: %x\n", hs.Checksum)
	fmt.Printf("Total Length: %d\n", hs.TotalLength)
	fmt.Printf("UUID: %x\n", hs.UUID)
	fmt.Printf("Data: %x\n", hs.Data)
```

출력 : 
```shell
Version: 4
Health Status: 0
Command: 341
Identification: 4660
Checksum: b8a2
Total Length: 28
UUID: 123456789abcdef01122334455667788
Data: aabcccdd
```



### Example.2 데이터 유효성 검사 (Checksum)

----

Checksum 계산 방법으로 IPv4 알고리즘을 사용했습니다.
1. 헤더를 2Byte 단위로 나눠서 더한다
2. 덧셈 결과가 2Byte 를 초과하면 올림수(Carry)를 하위 비트에 더한다. (2DE46 -> DE46 + 0002 = DE48)
3. 덧셈 결과에 1의 보수를 취한다.

코드 : 
```go
fmt.Printf("validate : %b \n", hsManager.ValidateCheckSum(packetData))
fmt.Printf("validate : %x \n", hsManager.GetCheckSum(packetData))
```

출력 :

```shell
validate : %!b(bool=true) 
validate : b8a2
```


### Example 3. toByte (직렬화)

<hr>

코드 :
```go
data2, err := hsManager.ToBytes(hs)
hs2, err := hsManager.Parsing(data2)
hsManager.PrintByte(data2)
```

출력 : 
```shell
0x41 0x55 0x12 0x34 0xB8 0xA2 0x00 0x1C 0x12 0x34 0x56 0x78 0x9A 0xBC 0xDE 0xF0 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0xAA 0xBC 0xCC 0xDD
```


## reference

----
### Command : 0 (0b0000000000)
#### 제목 : Ack
- Identification 에 대응되는 패킷을 잘 처리했음을 알림.

----

- 대표적으로 Agent 는 다음 4가지 요청을 보낼 수 있다.
- **get**/**post**/**update**/**delete**

### Command : 1 (0b0000000001)
#### 제목 : updateHealth
- Agent 가 자신의 UUID 기반으로 자신의 상태를 HealthStatus (HS) 필드에 담아서 전송합니다.
- 0b00 : stopping
- 0b01 : waiting (새로 생성)
- 0b10 : running 
- 0b11 : remove (삭제 요청)

### Command : 2 (0b0000000010)
#### 제목 : postSystemInfo 데이터
- Agent 가 컴퓨터의 정보를 json 형태로 전달함.
- 이때 데이터는 Data 필드의 josn 형태로 직렬화하여 보내짐.


### Command : 3 (0b0000000011)
#### 제목 : postSystemInfo 데이터
- Agent 가 컴퓨터의 정보를 json 형태로 전달함.
- 이때 데이터는 Data 필드의 josn 형태로 직렬화하여 보내짐


### Command : 4 (0b0000000100)
#### 제목 : postApplicationInfo 데이터
- Agent 가 ApplicationInfo 정보를 json 형태로 전달함.
- 이때 데이터는 Data 필드에 josn 형태로 직렬화하여 보내짐

### Command : 5 (0b0000000101)
#### 제목 : getPayload
- Agent 가 Sever 측에 공격 시나리오 (yaml 파일)을 요청함.
- 이때 데이터는 Data 필드에 yaml 형태로 직렬화하여 보내짐.

### Command : 6 (0b0000000110)
#### 제목 : postPayLoadLog
- Agent 가 Sever 측에 공격 시나리오 (yaml 파일)을 요청함.
- 이때 데이터는 Data 필드에 json 형태로 직렬화하여 보내짐


----

## 잡생각
- 아... 각 필드를 4bit 단위로 쪼개는 것이 편하다.
- command 를 0x0001 로 표현했으면 읽기 편했을 텐데, 애매하게 10 bit 로 표현해서 가독성이 안좋아졌네요.
- 


