package noise

import (
	"crypto/rand"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

const valueLimit = 65535

const sinkKey = "xray.finalmask.noise.sink"

type scriptSink struct {
	packets []scriptPacket
	open    bool
}

func RegisterLua(L *lua.LState) {
	registerLua(L, nil)
}

func registerLua(L *lua.LState, sink *scriptSink) {
	if sink != nil {
		data := L.NewUserData()
		data.Value = sink
		L.SetField(L.G.Registry, sinkKey, data)
	}

	L.PreloadModule("xray.finalmask.noise", func(L *lua.LState) int {
		module := L.CreateTable(0, 3)

		if sink != nil {
			module.RawSetString("Send", L.NewFunction(func(L *lua.LState) int {
				if !sink.open {
					L.RaiseError("noise.Send requires an active noise call")
					return 0
				}
				packet, ok := L.Get(1).(lua.LString)
				if !ok {
					L.RaiseError("noise.Send requires a packet string")
					return 0
				}
				var delay int64
				switch value := L.Get(2).(type) {
				case *lua.LNilType:
				case lua.LNumber:
					if delay = int64(value); delay < 0 || delay > valueLimit {
						L.RaiseError("noise.Send requires a delay of 0 to %d milliseconds", valueLimit)
						return 0
					}
				default:
					L.RaiseError("noise.Send requires a delay in milliseconds")
					return 0
				}
				sink.packets = append(sink.packets, scriptPacket{
					packet: []byte(packet),
					delay:  time.Duration(delay) * time.Millisecond,
				})
				return 0
			}))
		}

		module.RawSetString("Random", L.NewFunction(func(L *lua.LState) int {
			size := L.CheckInt(1)
			if size < 0 || size > valueLimit {
				L.RaiseError("noise.Random requires a size of 0 to %d", valueLimit)
				return 0
			}
			buf := make([]byte, size)
			if _, err := rand.Read(buf); err != nil {
				L.RaiseError("noise.Random failed: %v", err)
				return 0
			}
			xlua.PushString(L, string(buf))
			return 1
		}))

		module.RawSetString("RandomBetween", L.NewFunction(func(L *lua.LState) int {
			from, to := L.CheckInt64(1), L.CheckInt64(2)
			if from < 0 || from > to || to > valueLimit {
				L.RaiseError("noise.RandomBetween requires 0 <= from <= to <= %d", valueLimit)
				return 0
			}
			xlua.PushNumber(L, crypto.RandBetween(from, to+1))
			return 1
		}))

		L.Push(module)
		return 1
	})
}

func luaSink(L *lua.LState) (*scriptSink, error) {
	return xlua.ReadUserData[*scriptSink](L.GetField(L.G.Registry, sinkKey), "noise script has no sink")
}

func callLuaNoise(L *lua.LState, sink *scriptSink, addr string) error {
	fn := L.GetGlobal("HandleNoise")
	if fn.Type() != lua.LTFunction {
		return errors.New("noise script must define HandleNoise(...)")
	}

	sink.packets, sink.open = sink.packets[:0], true
	defer func() { sink.open = false }()

	return L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, lua.LString(addr))
}

func readLuaNoiseResult(L *lua.LState, sink *scriptSink) ([]scriptPacket, error) {
	if err := xlua.ReadError(L.Get(-1), "noise script error must be an error or a string"); err != nil {
		return nil, err
	}
	return sink.packets, nil
}
