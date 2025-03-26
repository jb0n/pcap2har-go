package tcp

import (
	"io"
	"sync"

	gpkt "github.com/jb0n/pcap2har-go/pcap-cli/internal/gopacket"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/tcpassembly"
)

type ConnectionReader interface {
	ReadStream(r Stream, a, b gopacket.Flow, completed chan interface{})
}

type StreamFactory struct {
	reader    ConnectionReader
	wg        sync.WaitGroup
	completed chan interface{}
}

func NewFactory(r ConnectionReader) *StreamFactory {
	return &StreamFactory{
		reader:    r,
		completed: make(chan interface{}),
	}
}

func (f *StreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := gpkt.NewReaderStream()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.reader.ReadStream(&r, a, b, f.completed)
	}()
	return &r
}

func (f *StreamFactory) Output(w io.Writer, outputFunc func(io.Writer, chan interface{})) {
	go func() {
		f.wg.Wait()
		close(f.completed)
	}()

	outputFunc(w, f.completed)
}
