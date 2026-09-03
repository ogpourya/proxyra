package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dop251/goja"
)

// jsMatcher holds validated JS source defining function match(url, body, status, headers).
// goja runtimes are not goroutine-safe, so each worker builds its own runner.
type jsMatcher struct {
	src string
}

type jsRunner struct {
	vm *goja.Runtime
	fn goja.Callable
}

func loadJSMatcher(arg string) (*jsMatcher, error) {
	src := arg
	if fi, err := os.Stat(arg); err == nil && !fi.IsDir() {
		b, err := os.ReadFile(arg)
		if err != nil {
			return nil, fmt.Errorf("read js file: %w", err)
		}
		src = string(b)
	}
	m := &jsMatcher{src: src}
	if _, err := m.newRunner(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *jsMatcher) newRunner() (*jsRunner, error) {
	vm := goja.New()
	if _, err := vm.RunString(m.src); err != nil {
		return nil, fmt.Errorf("js compile: %w", err)
	}
	fn, ok := goja.AssertFunction(vm.Get("match"))
	if !ok {
		return nil, fmt.Errorf("js must define function match(url, body, status, headers)")
	}
	return &jsRunner{vm: vm, fn: fn}, nil
}

// match calls match(url, body, status, headers); truthy return passes.
// ponytail: 5s interrupt guard; a hanging script must not stall a worker forever.
func (r *jsRunner) match(target, body string, status int, headers string) bool {
	done := make(chan struct{})
	defer close(done)
	timer := time.AfterFunc(5*time.Second, func() {
		select {
		case <-done:
		default:
			r.vm.Interrupt("js timeout")
		}
	})
	defer timer.Stop()

	v, err := r.fn(goja.Undefined(),
		r.vm.ToValue(target),
		r.vm.ToValue(body),
		r.vm.ToValue(status),
		r.vm.ToValue(headers))
	if err != nil {
		return false
	}
	return v.ToBoolean()
}
