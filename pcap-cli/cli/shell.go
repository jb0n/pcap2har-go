package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/jb0n/pcap2har-go/internal/har"
	"github.com/jb0n/pcap2har-go/internal/reader"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"
	jsoniter "github.com/json-iterator/go"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/spf13/pflag"
)

func Main(_ string, r tcp.ConnectionReader, outputFunc func(io.Writer, chan any)) {
	var assemblyDebug, displayVersion bool
	var serverPorts []int32

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.BoolVar(&assemblyDebug, "assembly-debug", false, "Debug log from the tcp assembly")
	pflag.Int32SliceVar(&serverPorts, "server-ports", []int32{}, "Server ports")
	pflag.Parse()

	if displayVersion {
		fmt.Printf("Version: %s\n", Version)
		return
	}

	if assemblyDebug {
		// set the flag the pcap library reads to
		// know it needs to output debug info.
		if err := flag.Set("assembly_debug_log", "true"); err != nil {
			log.Fatal(err)
		}
	}

	files := pflag.Args()

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	streamFactory := tcp.NewFactory(r)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					if allowPort(serverPorts, tcp) {
						assembler.AssembleWithTimestamp(
							packet.NetworkLayer().NetworkFlow(),
							tcp, packet.Metadata().Timestamp)
					}
				}
			}
		}
	}

	assembler.FlushAll()

	streamFactory.Output(os.Stdout, outputFunc)
}

func Convert(files []string) ([]byte, error) {
	r := reader.New()
	streamFactory := tcp.NewFactory(r)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		handle, err := pcap.OpenOffline(filename)
		if err != nil {
			return nil, fmt.Errorf("pcap.OpenOffline on %s failed. err=%w", filename, err)
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)
			}
		}
	}

	assembler.FlushAll()
	buf := &bytes.Buffer{}
	rdr := reader.New()
	streamFactory.Output(buf, convertOutputFunc(rdr))
	return buf.Bytes(), nil
}

func convertOutputFunc(r *reader.HTTPConversationReaders) func(io.Writer, chan any) {
	return func(w io.Writer, completed chan any) {
		var har har.Har
		har.Log.Version = "1.2"
		har.Log.Creator.Name = "pcap2har"
		har.Log.Creator.Version = Version

		<-completed

		c := r.GetConversations()
		for _, v := range c {
			har.AddEntry(v)
		}
		har.FinaliseAndSort()

		var json = jsoniter.ConfigCompatibleWithStandardLibrary
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		err := e.Encode(har)
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func allowPort(serverPorts []int32, packet *layers.TCP) bool {
	if len(serverPorts) == 0 {
		return true
	}

	for _, port := range serverPorts {
		if packet.SrcPort == layers.TCPPort(port) || packet.DstPort == layers.TCPPort(port) { //nolint
			return true
		}
	}

	return false
}

func SimpleJSONOutput(o io.Writer, completed chan any) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("  ", "  ")

	fmt.Fprint(o, "[\n  ")
	first := true
	for c := range completed {
		if first {
			first = false
		} else {
			// this sucks.
			fmt.Fprintf(o, "  ,\n  ")
		}
		err := e.Encode(c)
		if err != nil {
			log.Println(o, err)
			return
		}
	}
	fmt.Fprintln(o, "]")
}
