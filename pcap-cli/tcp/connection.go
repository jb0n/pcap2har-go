package tcp

import (
	"encoding/json"
	"fmt"

	"github.com/gopacket/gopacket"
)

type ConnectionAddress struct {
	IP, Port gopacket.Flow
}

func (c ConnectionAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c ConnectionAddress) String() string {
	src, dest := c.IP.Endpoints()
	sPort, dPort := c.Port.Endpoints()

	return fmt.Sprintf("%s:%s - %s:%s", src, sPort, dest, dPort)
}
