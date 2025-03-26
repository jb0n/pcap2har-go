package general

import (
	"io"
	"io/ioutil"
	"log"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"
)

type ConnectionBuilderFactory interface {
	NewBuilder(address tcp.ConnectionAddress, completed chan interface{}) ConnectionBuilder
}

type ConnectionBuilder interface {
	ReadClientStream(s *tcp.TimeCaptureReader) error
	ReadServerStream(s *tcp.TimeCaptureReader) error
	ReadDone()
}

type Reader struct {
	mu       sync.Mutex
	builders map[tcp.ConnectionAddress]ConnectionBuilder
	factory  ConnectionBuilderFactory
	Verbose  bool
}

func NewReader(factory ConnectionBuilderFactory) *Reader {
	return &Reader{
		factory:  factory,
		builders: make(map[tcp.ConnectionAddress]ConnectionBuilder),
	}
}

func (r *Reader) ReadStream(s tcp.Stream, a, b gopacket.Flow, completed chan interface{}) {
	t := tcp.NewTimeCaptureReader(s)
	src, dest := b.Endpoints()

	var address tcp.ConnectionAddress
	response := false
	if src.LessThan(dest) {
		address = tcp.ConnectionAddress{IP: a.Reverse(), Port: b.Reverse()}
		response = true
	} else {
		address = tcp.ConnectionAddress{IP: a, Port: b}
	}
	builder := r.ConnectionBuilder(address, completed)
	defer builder.ReadDone()

	var err error
	if response {
		err = builder.ReadServerStream(t)
	} else {
		err = builder.ReadClientStream(t)
	}
	if err != nil && err != io.EOF {
		if r.Verbose {
			log.Printf("Error on response: %s\n", err)
		}
		// not much we can do about errors here.
		//nolint:errcheck
		io.Copy(ioutil.Discard, t)
	}
}

func (r *Reader) ConnectionBuilder(
	address tcp.ConnectionAddress,
	completed chan interface{},
) ConnectionBuilder {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.builders[address]
	if !ok {
		b = r.factory.NewBuilder(address, completed)
		r.builders[address] = b
	}
	return b
}
