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
	// poison: unknown mask type, xray -test rejects it
	poison, err := ParseLink(`vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443?security=none&encryption=none&fm={"tcp":[{"type":"nosuchmask"}]}#poison`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddOutbound(poison); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("start 251 inbounds (3 batches): %v", err)
	}
	defer m.StopAll()
	insts := m.Instances()
	if len(insts) != 250 {
		t.Fatalf("want 250 live instances (poison excluded), got %d", len(insts))
	}
	seen := map[int]struct{}{}
	for _, inst := range insts {
		if _, dup := seen[inst.Port]; dup {
			t.Fatalf("dup port %d", inst.Port)
		}
		seen[inst.Port] = struct{}{}
	}
	if len(m.cmds) != 3 {
		t.Fatalf("want 3 xray processes, got %d", len(m.cmds))
	}
}
