package main

import (
	"fmt"
	"github.com/HTTPs-omma/HSProtocol/HSProtocol"
	"log"
)

func main() {
	// Example byte slice representing an HS packet
	packetData := []byte{
		0x41, 0x55, // Version: 4 (0100), HealthStatus: 1 (01), Command: 341 (0101010101)
		0x12, 0x34, // Identification: 0x1234
		0xb8, 0xa2, // Checksum: 0x4112
		0x00, 0x1C, // TotalLength: 001C : 28
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // UUID part 1
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // UUID part 2
		0xAA, 0xBC, 0xCC, 0xDD, 0xFF, // Data start
	}

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

	fmt.Printf("validate : %b \n", hsManager.ValidateCheckSum(packetData))
	fmt.Printf("validate : %x \n", hsManager.GetCheckSum(packetData))
	fmt.Printf("======================== \n")

	data2, err := hsManager.ToBytes(hs)
	hs2, err := hsManager.Parsing(data2)
	fmt.Printf("Version: %d\n", hs2.Version)
	fmt.Printf("Health Status: %d\n", hs2.HealthStatus)
	fmt.Printf("Command: %d\n", hs2.Command)
	fmt.Printf("Identification: %d\n", hs2.Identification)
	fmt.Printf("Checksum: %x\n", hs2.Checksum)
	fmt.Printf("Total Length: %d\n", hs2.TotalLength)
	fmt.Printf("UUID: %x\n", hs2.UUID)
	fmt.Printf("Data: %x\n", hs2.Data)
	fmt.Printf("validate : %b \n", hsManager.ValidateCheckSum(data2))
	fmt.Printf("validate : %x \n", hsManager.GetCheckSum(data2))
	fmt.Printf("======================== \n")

	data3, err := hsManager.ToBytes(hs2)
	hs3, err := hsManager.Parsing(data3)
	fmt.Printf("Version: %d\n", hs3.Version)
	fmt.Printf("Health Status: %d\n", hs3.HealthStatus)
	fmt.Printf("Command: %d\n", hs3.Command)
	fmt.Printf("Identification: %d\n", hs3.Identification)
	fmt.Printf("Checksum: %x\n", hs3.Checksum)
	fmt.Printf("Total Length: %d\n", hs3.TotalLength)
	fmt.Printf("UUID: %x\n", hs3.UUID)
	fmt.Printf("Data: %x\n", hs3.Data)
	fmt.Printf("validate : %b \n", hsManager.ValidateCheckSum(data3))
	fmt.Printf("validate : %x \n", hsManager.GetCheckSum(data3))
	hsManager.PrintByte(data3)
}
