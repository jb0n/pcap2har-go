package example

import (
	"bytes"
	"io"
	"sync"

	"github.com/jb0n/pcap2har-go/pcap-cli/general"
	"github.com/jb0n/pcap2har-go/pcap-cli/tcp"
)

const bothSides = 2

type Connection struct {
	Address      string
	ClientStream []byte
	ServerStream []byte
}

type ConnectionBuilder struct {
	address       tcp.ConnectionAddress
	completed     chan interface{}
	sidesComplete uint8
	mu            sync.Mutex
	clientData    bytes.Buffer
	serverData    bytes.Buffer
}

func (b *ConnectionBuilder) ReadClientStream(s *tcp.TimeCaptureReader) error {
	_, err := io.Copy(&b.clientData, s)
	return err
}

func (b *ConnectionBuilder) ReadServerStream(s *tcp.TimeCaptureReader) error {
	_, err := io.Copy(&b.serverData, s)
	return err
}

func (b *ConnectionBuilder) ReadDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sidesComplete++
	if b.sidesComplete == bothSides {
		b.completed <- &Connection{
			Address:      b.address.String(),
			ClientStream: b.clientData.Bytes(),
			ServerStream: b.serverData.Bytes(),
		}
	}
}

type ConnectionBuilderFactory struct{}

func (f *ConnectionBuilderFactory) NewBuilder(
	address tcp.ConnectionAddress, completed chan interface{},
) general.ConnectionBuilder {
	return &ConnectionBuilder{address: address, completed: completed}
}
