//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/jb0n/pcap2har-go/internal/reader"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
)

func Fuzz(data []byte) int {

	streamFactory := &tcp.StreamFactory{
		Reader: reader.New(),
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	if handle, err := pcap.OpenOffline(tmpfile.Name()); err != nil {
		return 0
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			// NOTE: just pushing all TCP through it on the basis it might
			// be http.
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)
			}
		}
	}

	assembler.FlushAll()
	//fmt.Printf("Found %d connections\n", connections)
	streamFactory.Reader.GetConversations()
	return 0
}
