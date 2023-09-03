package main

import (
	"fmt"
	"log"
	"time"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Open the device for capturing
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetChan := make(chan gopacket.Packet, 1000)

	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		go packetWorker(packetChan)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}
}

func packetWorker(ch <- chan gopacket.Packet) {
	for packet := range ch {
		// Print the timestamp
		timestamp := packet.Metadata().Timestamp
		if timestamp.IsZero() {
			timestamp = time.Now()
		}
		fmt.Printf("Timestamp: %s\n", timestamp.Format(time.RFC3339Nano))

		// Print IP layer details
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("From IP: %s\n", ip.SrcIP)
			fmt.Printf("To IP: %s\n", ip.DstIP)
		}

		// Print TCP layer details
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From port: %d\n", tcp.SrcPort)
			fmt.Printf("To port: %d\n", tcp.DstPort)
			fmt.Printf("Sequence number: %d\n", tcp.Seq)

			// TCP Flags
				flags := []string{}
			if tcp.FIN {
				flags = append(flags, "FIN")
			}
			if tcp.SYN {
				flags = append(flags, "SYN")
			}
			if tcp.RST {
				flags = append(flags, "RST")
			}
			if tcp.PSH {
				flags = append(flags, "PSH")
			}
			if tcp.ACK {
				flags = append(flags, "ACK")
			}
			if tcp.URG {
				flags = append(flags, "URG")
			}
			if tcp.ECE {
				flags = append(flags, "ECE")
			}
			if tcp.CWR {
				flags = append(flags, "CWR")
			}
			if len(flags) > 0 {
				fmt.Printf("Flags: %s\n", strings.Join(flags, ","))
			}
		}

		fmt.Println("--------------------------------------------")

		processPacket(packet)
	}
}

type ConnectionKey struct {
    SrcIP   string
    SrcPort int
    DstIP   string
    DstPort int
    SeqNum  uint32
}

var syns sync.Map

func processPacket(packet gopacket.Packet) {
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)

        // Create a connection key for this packet
        connKey := createConnectionKey(packet)

        if tcp.SYN && !tcp.ACK {
            // This is a SYN packet
            storeSYNPacket(connKey, packet.Metadata().Timestamp)
        } else if tcp.SYN && tcp.ACK {
            // This is a SYN-ACK packet
            handleSYNACKPacket(connKey, packet.Metadata().Timestamp)
        }
    }
}

func createConnectionKey(packet gopacket.Packet) ConnectionKey {
    // Extract the required fields from the packet (IPs, ports) to create a ConnectionKey
    // This is a simplified example, actual extraction might be more complex.
    ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
    tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

    if tcpLayer.SYN && !tcpLayer.ACK {
        return ConnectionKey{
            SrcIP:   ipLayer.SrcIP.String(),
            SrcPort: int(tcpLayer.SrcPort),
            DstIP:   ipLayer.DstIP.String(),
            DstPort: int(tcpLayer.DstPort),
            SeqNum:  uint32(tcpLayer.Seq),
        }
    }

    // If the packet is a SYN-ACK, reverse the IPs and ports, but keep the sequence number.
    if tcpLayer.SYN && tcpLayer.ACK {
        return ConnectionKey{
            SrcIP:   ipLayer.DstIP.String(),
            SrcPort: int(tcpLayer.DstPort),
            DstIP:   ipLayer.SrcIP.String(),
            DstPort: int(tcpLayer.SrcPort),
            SeqNum:  uint32(tcpLayer.Ack) - 1, // The sequence number in the SYN-ACK will be original sequence number + 1
        }
    }

    return ConnectionKey{}
}

func storeSYNPacket(connKey ConnectionKey, timestamp time.Time) {
    syns.Store(connKey, timestamp)
    fmt.Println("Map:", syns)
}

func handleSYNACKPacket(connKey ConnectionKey, synAckTimestamp time.Time) {
    fmt.Println("HERE!!")
    // Try to retrieve the corresponding SYN timestamp
    if synTimestamp, ok := syns.Load(connKey); ok {
        latency := synAckTimestamp.Sub(synTimestamp.(time.Time))
        fmt.Printf("Latency: %v\n", latency)

        // Remove the SYN packet from the map to free up space
        syns.Delete(connKey)
    }
}

