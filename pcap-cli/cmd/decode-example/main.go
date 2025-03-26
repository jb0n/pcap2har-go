package main

import (
	"github.com/jb0n/pcap2har-go/pcap-cli/cli"
	"github.com/jb0n/pcap2har-go/pcap-cli/example"
	"github.com/jb0n/pcap2har-go/pcap-cli/general"
	"github.com/spf13/pflag"
)

func main() {
	f := example.ConnectionBuilderFactory{}
	r := general.NewReader(&f)
	pflag.BoolVar(&r.Verbose, "verbose", false, "Verbose about things errors")
	cli.Main("", r, cli.SimpleJSONOutput)
}
