package sploit;

import(
	"testing"
)

// TestNewRemote tests Remote initialization
func TestNewRemote(t *testing.T) {
	r, err := NewRemote("localhost:8000")
	if err != nil {
		t.Fatal(err)
	}

	if r.Host != "localhost" {
		t.Fatal("Host != localhost")
	}

	if r.Port != 8000 {
		t.Fatal("Port != 8000")
	}
}
