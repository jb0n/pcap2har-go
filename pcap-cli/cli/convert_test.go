package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jb0n/pcap2har-go/pcap-cli/cli"
)

// The capture holds node --tls-keylog traffic: TLS 1.3, and TLS 1.2 and 1.0 suites that include CBC with
// encrypt-then-MAC, which OpenSSL negotiates and Go does not.
func TestConvertWithKeylog(t *testing.T) {
	out, summary, err := cli.ConvertWithKeylog([]string{"../../test/captures/tls.pcap"}, "../../test/captures/tls.keylog")
	if err != nil {
		t.Fatal(err)
	}
	var har struct {
		Log struct {
			Entries []struct {
				Request  struct{ URL string }
				Response struct{ Content struct{ Text string } }
			}
		}
	}
	if err := json.Unmarshal(out, &har); err != nil {
		t.Fatal(err)
	}
	if len(har.Log.Entries) != 10 {
		t.Fatalf("got %d entries, want 10 (summary: %s)", len(har.Log.Entries), summary)
	}
	for _, e := range har.Log.Entries {
		if !strings.HasPrefix(e.Request.URL, "https://") || !strings.HasPrefix(e.Response.Content.Text, "reply to ") {
			t.Errorf("entry not decrypted: %s -> %q", e.Request.URL, e.Response.Content.Text)
		}
	}
}

func TestConvertBadKeylog(t *testing.T) {
	if _, _, err := cli.ConvertWithKeylog([]string{"../../test/captures/tls.pcap"}, "missing.keylog"); err == nil {
		t.Fatal("a missing key log converted")
	}
}
