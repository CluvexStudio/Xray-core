package noise

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

func newScriptConn(t *testing.T, script string) (*noiseConn, *fakePacketConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, script))
	raw := &fakePacketConn{}
	conn, err := NewConnClient(&Config{Script: path}, raw)
	require.NoError(t, err)
	return conn.(*noiseConn), raw
}

func newScriptConnError(t *testing.T, script string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, script))
	_, err := NewConnClient(&Config{Script: path}, &fakePacketConn{})
	return err
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestScriptSendsStrings(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("first")
    noise.Send("second")
end
`)
	n, err := conn.WriteTo([]byte("payload"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443})
	require.NoError(t, err)
	require.Equal(t, 7, n)
	require.Equal(t, [][]byte{[]byte("first"), []byte("second"), []byte("payload")}, raw.packets())
}

func TestScriptSendsTables(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("a")
    noise.Send("bb", 0)
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("a"), []byte("bb"), []byte("p")}, raw.packets())
}

func TestScriptDelaysPackets(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("x", 60)
end
`)
	start := time.Now()
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Since(start), 60*time.Millisecond)
	require.Equal(t, [][]byte{[]byte("x"), []byte("p")}, raw.packets())
}

func TestScriptReceivesAddress(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send(address)
end
`)
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 8443}
	_, err := conn.WriteTo([]byte("p"), addr)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte(addr.String()), []byte("p")}, raw.packets())
}

func TestScriptSendsNoNoise(t *testing.T) {
	for name, script := range map[string]string{
		"sends nothing":  "function HandleNoise(address) end",
		"returns nil":    "function HandleNoise(address) return nil end",
		"returns a zero": "function HandleNoise(address) return 0 end",
	} {
		t.Run(name, func(t *testing.T) {
			conn, raw := newScriptConn(t, script)
			_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, [][]byte{[]byte("p")}, raw.packets())
		})
	}
}

func TestScriptRandom(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    local size = noise.RandomBetween(20, 20)
    noise.Send(noise.Random(size))
    noise.Send(noise.Random(0))
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	packets := raw.packets()
	require.Len(t, packets, 3)
	require.Len(t, packets[0], 20)
	require.Empty(t, packets[1])
}

func TestScriptRandomBetweenStaysInRange(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    for i = 1, 200 do
        noise.Send(string.rep("x", noise.RandomBetween(1, 3)))
    end
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	packets := raw.packets()
	require.Len(t, packets, 201)
	sizes := make(map[int]bool)
	for _, packet := range packets[:200] {
		require.GreaterOrEqual(t, len(packet), 1)
		require.LessOrEqual(t, len(packet), 3)
		sizes[len(packet)] = true
	}
	require.Len(t, sizes, 3, "every size in the range should show up")
}

func TestScriptKeepsStateBetweenPeers(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")
local sent = 0

function HandleNoise(address)
    sent = sent + 1
    noise.Send(string.rep("x", sent))
end
`)
	for i := 1; i <= 3; i++ {
		_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: i})
		require.NoError(t, err)
	}
	require.Equal(t, [][]byte{
		[]byte("x"), []byte("p"),
		[]byte("xx"), []byte("p"),
		[]byte("xxx"), []byte("p"),
	}, raw.packets())
}

func TestScriptRunsOncePerPeerUntilReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))
	raw := &fakePacketConn{}
	conn, err := NewConnClient(&Config{Script: path, ResetMin: 0, ResetMax: 0}, raw)
	require.NoError(t, err)

	addr := &net.UDPAddr{Port: 1}
	for i := 0; i < 3; i++ {
		_, err := conn.WriteTo([]byte("p"), addr)
		require.NoError(t, err)
	}
	require.Equal(t, [][]byte{[]byte("n"), []byte("p"), []byte("p"), []byte("p")}, raw.packets())
}

func TestScriptRunsAgainAfterReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))
	raw := &fakePacketConn{}
	conn, err := NewConnClient(&Config{Script: path, ResetMin: 0, ResetMax: 1}, raw)
	require.NoError(t, err)
	noiseConn := conn.(*noiseConn)

	addr := &net.UDPAddr{Port: 1}
	_, err = noiseConn.WriteTo([]byte("p"), addr)
	require.NoError(t, err)
	noiseConn.m[addr.String()] = time.Now().Add(-time.Second)
	_, err = noiseConn.WriteTo([]byte("p"), addr)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("n"), []byte("p"), []byte("n"), []byte("p")}, raw.packets())
}

func TestScriptFailureStillSendsPayload(t *testing.T) {
	for name, script := range map[string]string{
		"raises":           `function HandleNoise(address) error("boom") end`,
		"reports an error": `function HandleNoise(address) return "nope" end`,
		"packet is a bool": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send(true) end`,
		"packet is a number": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send(5) end`,
		"no packet": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send() end`,
		"delay is negative": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("x", -1) end`,
		"delay is too big": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("x", 65536) end`,
		"delay is not a number": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("x", "soon") end`,
	} {
		t.Run(name, func(t *testing.T) {
			conn, raw := newScriptConn(t, script)
			n, err := conn.WriteTo([]byte("payload"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, 7, n)
			require.Equal(t, [][]byte{[]byte("payload")}, raw.packets())
		})
	}
}

func TestScriptFailsToLoad(t *testing.T) {
	for name, script := range map[string]string{
		"no HandleNoise":      `function Other() end`,
		"HandleNoise is data": `HandleNoise = 1`,
		"syntax error":        `function HandleNoise(`,
		"top level error":     `error("boom")`,
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, newScriptConnError(t, script))
		})
	}
}

func TestScriptMissingFile(t *testing.T) {
	_, err := NewConnClient(&Config{Script: filepath.Join(t.TempDir(), "absent.lua")}, &fakePacketConn{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to initialize the noise script")
}

func TestInitScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))

	require.NoError(t, (&Config{}).InitScript(), "no script is not an error")

	config := &Config{Script: path}
	require.NoError(t, config.InitScript())
	engine, err := config.engine()
	require.NoError(t, err)

	conn, err := NewConnClient(config, &fakePacketConn{})
	require.NoError(t, err)
	require.Same(t, engine, conn.(*noiseConn).script, "a connection reuses the pool from startup")
}

func TestInitScriptFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `function Other() end`))
	require.Error(t, (&Config{Script: path}).InitScript())
	require.Error(t, (&Config{Script: filepath.Join(t.TempDir(), "absent.lua")}).InitScript())
}

func TestScriptIsSharedPerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))

	config := &Config{Script: path}
	first, err := NewConnClient(config, &fakePacketConn{})
	require.NoError(t, err)
	second, err := NewConnClient(config, &fakePacketConn{})
	require.NoError(t, err)
	require.Same(t, first.(*noiseConn).script, second.(*noiseConn).script,
		"the same config reuses its pool")

	other, err := NewConnClient(&Config{Script: path}, &fakePacketConn{})
	require.NoError(t, err)
	require.NotSame(t, first.(*noiseConn).script, other.(*noiseConn).script,
		"another config naming the same file gets its own pool")
}

func TestScriptStateIsNotSharedBetweenConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `
local noise = require("xray.finalmask.noise")
local calls = 0

function HandleNoise(address)
    calls = calls + 1
    noise.Send(string.rep("x", calls))
end
`))
	for i := 0; i < 2; i++ {
		raw := &fakePacketConn{}
		conn, err := NewConnClient(&Config{Script: path}, raw)
		require.NoError(t, err)
		_, err = conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
		require.NoError(t, err)
		require.Equal(t, [][]byte{[]byte("x"), []byte("p")}, raw.packets())
	}
}

func TestScriptReportsAnError(t *testing.T) {
	for name, script := range map[string]string{
		"after sending": `local noise = require("xray.finalmask.noise")
function HandleNoise(address)
    noise.Send("n")
    return "not today"
end`,
		"without sending": `function HandleNoise(address) return "not today" end`,
	} {
		t.Run(name, func(t *testing.T) {
			conn, raw := newScriptConn(t, script)
			_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, [][]byte{[]byte("p")}, raw.packets())
		})
	}
}

func TestScriptInstanceSurvivesABadReturn(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")
local calls = 0

function HandleNoise(address)
    calls = calls + 1
    if calls == 1 then
        return "first call refused"
    end
    noise.Send("call-" .. calls)
end
`)
	for i := 1; i <= 2; i++ {
		_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: i})
		require.NoError(t, err)
	}
	require.Equal(t, [][]byte{[]byte("p"), []byte("call-2"), []byte("p")}, raw.packets(),
		"a refused return value keeps the instance, so its counter survives")
}

func TestScriptInstanceIsDroppedAfterAnException(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")
local calls = 0

function HandleNoise(address)
    calls = calls + 1
    if calls == 1 then
        error("boom")
    end
    noise.Send("call-" .. calls)
end
`)
	for i := 1; i <= 2; i++ {
		_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: i})
		require.NoError(t, err)
	}
	require.Equal(t, [][]byte{[]byte("p"), []byte("p")}, raw.packets(),
		"an exception destroys the instance, so the next call gets a fresh counter and raises again")
}

func TestScriptCanLog(t *testing.T) {
	conn, raw := newScriptConn(t, `
local log = require("xray.log")
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    log.Debug("noise for ", address)
    noise.Send("n")
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("n"), []byte("p")}, raw.packets())
}

func TestScriptRandomRejectsBadArguments(t *testing.T) {
	for name, script := range map[string]string{
		"negative size":  `function HandleNoise(address) require("xray.finalmask.noise").Random(-1) end`,
		"reversed range": `function HandleNoise(address) require("xray.finalmask.noise").RandomBetween(5, 1) end`,
	} {
		t.Run(name, func(t *testing.T) {
			conn, raw := newScriptConn(t, script)
			_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, [][]byte{[]byte("p")}, raw.packets())
		})
	}
}

func TestScriptStaticNoiseStillWorks(t *testing.T) {
	raw := &fakePacketConn{}
	conn, err := NewConnClient(&Config{Items: []*Item{{Packet: []byte("static")}}}, raw)
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("static"), []byte("p")}, raw.packets())
	require.Nil(t, conn.(*noiseConn).script)
}

func TestScriptSendsInOrder(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("first")
    noise.Send("second")
    noise.Send("third")
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("first"), []byte("second"), []byte("third"), []byte("p")}, raw.packets())
}

func TestScriptBinaryPacket(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("\0\1\255")
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{{0x00, 0x01, 0xff}, []byte("p")}, raw.packets())
}

func TestScriptNameInLoadError(t *testing.T) {
	err := newScriptConnError(t, `function HandleNoise(`)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "noise.lua"), err.Error())
}

func TestScriptOnServerConn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))
	raw := &fakePacketConn{}
	conn, err := NewConnServer(&Config{Script: path}, raw)
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("n"), []byte("p")}, raw.packets())
}

func TestScriptDropsHandleNoise(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    HandleNoise = nil
    noise.Send("once")
end
`)
	for i := 1; i <= 2; i++ {
		_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: i})
		require.NoError(t, err)
	}
	require.Equal(t, [][]byte{[]byte("once"), []byte("p"), []byte("p")}, raw.packets(),
		"a state that lost HandleNoise sends no noise instead of failing the write")
}

func TestScriptValueLimits(t *testing.T) {
	for name, script := range map[string]string{
		"random too big":        `function HandleNoise(address) require("xray.finalmask.noise").Random(65536) end`,
		"random bound too big":  `function HandleNoise(address) require("xray.finalmask.noise").RandomBetween(0, 65536) end`,
		"random bound negative": `function HandleNoise(address) require("xray.finalmask.noise").RandomBetween(-1, 1) end`,
		"delay too big": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("x", 65536) end`,
		"huge delay from a float": `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("x", 1e18) end`,
	} {
		t.Run(name, func(t *testing.T) {
			conn, raw := newScriptConn(t, script)
			_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
			require.NoError(t, err)
			require.Equal(t, [][]byte{[]byte("p")}, raw.packets())
		})
	}
}

func TestScriptValueLimitsAccepted(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send(noise.Random(65535))
    noise.Send("x", 0)
    noise.Send(tostring(noise.RandomBetween(65535, 65535)))
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	packets := raw.packets()
	require.Len(t, packets, 4)
	require.Len(t, packets[0], 65535)
	require.Equal(t, []byte("65535"), packets[2])
}

func TestScriptSendsManyPackets(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    for i = 1, 100 do
        noise.Send("n")
    end
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Len(t, raw.packets(), 101)
}

func TestScriptKeepsPacketsSentBeforeAnError(t *testing.T) {
	conn, raw := newScriptConn(t, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send("sent")
    error("boom")
end
`)
	_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: 1})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("p")}, raw.packets(),
		"an exception drops everything the call had queued")
}

func TestSendOutsideANoiseCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `
local noise = require("xray.finalmask.noise")

noise.Send("too early")

function HandleNoise(address)
end
`))
	_, err := NewConnClient(&Config{Script: path}, &fakePacketConn{})
	require.Error(t, err, "the top level cannot send noise")
}

func TestRegisterLuaHasNoSend(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	require.NoError(t, L.DoString(`
local noise = require("xray.finalmask.noise")
if noise.Send ~= nil then
    error("Send should not be exported to other modules")
end
assert(#noise.Random(4) == 4)
assert(noise.RandomBetween(3, 3) == 3)
`))
}

func TestEngineWithoutAScript(t *testing.T) {
	_, err := (&Config{}).engine()
	require.Error(t, err)
}

func TestScriptUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `
local noise = require("xray.finalmask.noise")

function HandleNoise(address)
    noise.Send(noise.Random(8))
    noise.Send(address, 1)
end
`))
	config := &Config{Script: path}
	raw := &fakePacketConn{}
	conn, err := NewConnClient(config, raw)
	require.NoError(t, err)

	const peers = 40
	var wg sync.WaitGroup
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			_, err := conn.WriteTo([]byte("p"), &net.UDPAddr{Port: port})
			require.NoError(t, err)
		}(i + 1)
	}
	wg.Wait()

	require.Len(t, raw.packets(), peers*3, "every peer gets two noise packets and its payload")
}

func TestEngineIsCreatedOnceUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `local noise = require("xray.finalmask.noise")
function HandleNoise(address) noise.Send("n") end`))
	config := &Config{Script: path}

	engines := make([]*scriptEngine, 16)
	var wg sync.WaitGroup
	for i := range engines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			engine, err := config.engine()
			require.NoError(t, err)
			engines[i] = engine
		}(i)
	}
	wg.Wait()

	for _, engine := range engines {
		require.Same(t, engines[0], engine)
	}
}

func TestPacketsWithoutASink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.lua")
	require.NoError(t, writeFile(path, `function HandleNoise(address) end`))
	program, err := xlua.CompileFile(path)
	require.NoError(t, err)
	pool, err := xlua.NewPool(context.Background(), time.Second,
		program.NewStateFactory(time.Minute, RegisterLua, nil))
	require.NoError(t, err)
	defer pool.Close()

	_, err = (&scriptEngine{pool: pool}).packets("192.0.2.1:443", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no sink")
}
