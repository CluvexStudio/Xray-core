package noise

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

const (
	scriptExecutionTimeout = time.Second
	scriptInitTimeout      = 120 * time.Second
)

type scriptEngine struct {
	pool *xlua.Pool
}

type scriptPacket struct {
	packet []byte
	delay  time.Duration
}

var (
	scriptsMu sync.Mutex
	scripts   = make(map[*Config]*scriptEngine)
)

func (c *Config) InitScript() error {
	if c.Script == "" {
		return nil
	}
	_, err := c.engine()
	return err
}

func (c *Config) engine() (*scriptEngine, error) {
	if c.Script == "" {
		return nil, errors.New("no noise script is configured")
	}

	scriptsMu.Lock()
	defer scriptsMu.Unlock()

	if engine := scripts[c]; engine != nil {
		return engine, nil
	}

	engine, err := newScriptEngine(c.Script)
	if err != nil {
		return nil, err
	}
	scripts[c] = engine
	return engine, nil
}

func newScriptEngine(path string) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}

	pool, err := xlua.NewPool(context.Background(), scriptExecutionTimeout, program.NewStateFactory(
		scriptInitTimeout,
		func(L *lua.LState) {
			log.RegisterLua(L)
			registerLua(L, &scriptSink{})
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleNoise").Type() != lua.LTFunction {
				return errors.New("noise script must define HandleNoise(...)")
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	return &scriptEngine{pool: pool}, nil
}

func (e *scriptEngine) packets(addr string, into []scriptPacket) ([]scriptPacket, error) {
	var scriptErr error
	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		sink, err := luaSink(L)
		if err != nil {
			return err
		}
		if err := callLuaNoise(L, sink, addr); err != nil {
			return err
		}
		var packets []scriptPacket
		packets, scriptErr = readLuaNoiseResult(L, sink)
		into = append(into, packets...)
		return nil
	}); err != nil {
		return nil, err
	}
	return into, scriptErr
}
