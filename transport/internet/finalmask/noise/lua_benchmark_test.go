package noise

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func benchmarkState(b *testing.B, script string) (*lua.LState, *scriptSink) {
	b.Helper()
	L := lua.NewState()
	b.Cleanup(L.Close)
	sink := &scriptSink{}
	registerLua(L, sink)
	if err := L.DoString(script); err != nil {
		b.Fatal(err)
	}
	L.SetContext(context.Background())
	return L, sink
}

func BenchmarkLuaNoiseHook(b *testing.B) {
	L, sink := benchmarkState(b, `
function HandleNoise(address)
end
`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := callLuaNoise(L, sink, "192.0.2.1:443"); err != nil {
			b.Fatal(err)
		}
		L.Pop(1)
	}
}

func BenchmarkLuaNoisePackets(b *testing.B) {
	b.Run("script", func(b *testing.B) {
		L, sink := benchmarkState(b, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send(noise.Random(64))
    noise.Send(noise.Random(64), 0)
end
`)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := callLuaNoise(L, sink, "192.0.2.1:443"); err != nil {
				b.Fatal(err)
			}
			packets, err := readLuaNoiseResult(L, sink)
			L.Pop(1)
			if err != nil {
				b.Fatal(err)
			}
			if len(packets) != 2 {
				b.Fatalf("got %d packets, want 2", len(packets))
			}
		}
	})

	b.Run("static", func(b *testing.B) {
		conn := &noiseConn{config: &Config{Items: []*Item{
			{RandMin: 64, RandMax: 64, RandRangeMax: 255},
			{RandMin: 64, RandMax: 64, RandRangeMax: 255},
		}}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, item := range conn.config.Items {
				if len(conn.buildPacket(item)) != 64 {
					b.Fatal("unexpected packet size")
				}
			}
		}
	})
}

func BenchmarkLuaNoiseWriteTo(b *testing.B) {
	path := filepath.Join(b.TempDir(), "noise.lua")
	if err := os.WriteFile(path, []byte(`
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send(noise.Random(64))
end
`), 0o600); err != nil {
		b.Fatal(err)
	}
	conn, err := NewConnClient(&Config{Script: path}, &benchmarkPacketConn{})
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte("payload")
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	if _, err := conn.WriteTo(payload, addr); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, addr); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkPacketConn struct{ net.PacketConn }

func (c *benchmarkPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
