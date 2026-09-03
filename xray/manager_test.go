package xray

import (
	"fmt"
	"testing"
)

func TestManagerBatches(t *testing.T) {
	m := NewManager()
	for i := 0; i < 250; i++ {
		ob, err := ParseLink(fmt.Sprintf("trojan://pw@127.0.0.1:443?security=tls#n%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.AddOutbound(ob); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int]struct{}{}
	for _, inst := range m.Instances() {
		if _, dup := seen[inst.Port]; dup {
			t.Fatalf("dup port %d", inst.Port)
		}
		seen[inst.Port] = struct{}{}
	}
	if err := m.Start(); err != nil {
		t.Fatalf("start 250 inbounds (3 batches): %v", err)
	}
	defer m.StopAll()
	if len(m.cmds) != 3 {
		t.Fatalf("want 3 xray processes, got %d", len(m.cmds))
	}
}
