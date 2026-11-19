package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pair(t *testing.T, ha, hb Handler) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	ca := NewConn(a, ha, Options{})
	cb := NewConn(b, hb, Options{})
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	return ca, cb
}

func echo(_ context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "echo":
		return params, nil
	case "fail":
		return nil, errors.New("boom")
	case "denied":
		return nil, Errorf(CodePermission, "permission denied: targets.exec")
	}
	return nil, Errorf(CodeMethodNotFound, "нет метода %s", method)
}

func TestCallBothDirections(t *testing.T) {
	ca, cb := pair(t, echo, echo)
	ctx := context.Background()
	var out map[string]int
	if err := ca.Call(ctx, "echo", map[string]int{"x": 1}, &out); err != nil || out["x"] != 1 {
		t.Fatalf("a→b: %v %v", out, err)
	}
	if err := cb.Call(ctx, "echo", map[string]int{"x": 2}, &out); err != nil || out["x"] != 2 {
		t.Fatalf("b→a: %v %v", out, err)
	}
	err := ca.Call(ctx, "fail", nil, nil)
	if !IsCode(err, CodeInternal) || err.Error() != "boom" {
		t.Fatalf("fail: %v", err)
	}
	if err := ca.Call(ctx, "denied", nil, nil); !IsCode(err, CodePermission) {
		t.Fatalf("denied: %v", err)
	}
	if err := ca.Call(ctx, "nope", nil, nil); !IsCode(err, CodeMethodNotFound) {
		t.Fatalf("nope: %v", err)
	}
}

// A handler may call back into the peer while serving a request (plugin
// apply → job.step on Hestia).
func TestNestedCalls(t *testing.T) {
	var cb *Conn
	ca, cbx := pair(t, func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		return "host:" + method, nil
	}, func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		var s string
		if err := cb.Call(ctx, "job.step", nil, &s); err != nil {
			return nil, err
		}
		return s + "+applied", nil
	})
	cb = cbx
	var out string
	if err := ca.Call(context.Background(), "apply", nil, &out); err != nil || out != "host:job.step+applied" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestConcurrentCalls(t *testing.T) {
	ca, _ := pair(t, nil, echo)
	errc := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func(i int) {
			var out int
			if err := ca.Call(context.Background(), "echo", i, &out); err != nil {
				errc <- err
				return
			}
			if out != i {
				errc <- errors.New("mixed up answers")
				return
			}
			errc <- nil
		}(i)
	}
	for i := 0; i < 50; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
}

// rawPeer gives the test the raw side of a connection.
func rawPeer(t *testing.T, h Handler) (*Conn, net.Conn, *bufio.Reader) {
	a, b := net.Pipe()
	c := NewConn(a, h, Options{})
	t.Cleanup(func() { _ = c.Close(); _ = b.Close() })
	return c, b, bufio.NewReader(b)
}

func readMsg(t *testing.T, r *bufio.Reader) Message {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return m
}

func TestBrokenMessages(t *testing.T) {
	_, raw, r := rawPeer(t, echo)
	for _, bad := range []string{"{not json", `{"jsonrpc":"1.0","id":1,"method":"echo"}`, `[1,2]`} {
		if _, err := io.WriteString(raw, bad+"\n"); err != nil {
			t.Fatal(err)
		}
		m := readMsg(t, r)
		if m.Error == nil || m.Error.Code != CodeParseError {
			t.Fatalf("%s: %+v", bad, m)
		}
	}
	// The connection survives broken messages.
	if _, err := io.WriteString(raw, `{"jsonrpc":"2.0","id":7,"method":"echo","params":"hi"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	m := readMsg(t, r)
	if string(m.ID) != "7" || string(m.Result) != `"hi"` {
		t.Fatalf("%+v", m)
	}
	// Empty lines are ignored; responses to unknown ids too.
	_, _ = io.WriteString(raw, "\n"+`{"jsonrpc":"2.0","id":99,"result":1}`+"\n")
	_, _ = io.WriteString(raw, `{"jsonrpc":"2.0","id":8,"method":"echo","params":1}`+"\n")
	if m := readMsg(t, r); string(m.ID) != "8" {
		t.Fatalf("%+v", m)
	}
}

func TestLongLineClosesConnection(t *testing.T) {
	c, raw, _ := rawPeer(t, echo)
	go func() {
		big := `{"jsonrpc":"2.0","method":"x","params":"` + strings.Repeat("a", MaxLine) + `"}` + "\n"
		_, _ = io.WriteString(raw, big)
	}()
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("connection not closed")
	}
	if !errors.Is(c.Err(), ErrLineTooLong) {
		t.Fatalf("err = %v", c.Err())
	}
}

func TestSendTooLong(t *testing.T) {
	ca, _ := pair(t, nil, echo)
	err := ca.Call(context.Background(), "echo", strings.Repeat("a", MaxLine), nil)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err = %v", err)
	}
}

func TestCancel(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	ca, _ := pair(t, nil, func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- ca.CallNoTimeout(ctx, "apply", nil, nil) }()
	<-started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not cancelled by $/cancel")
	}
}

func TestCancelledHandlerAnswersWithCode(t *testing.T) {
	c, raw, r := rawPeer(t, func(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_ = c
	_, _ = io.WriteString(raw, `{"jsonrpc":"2.0","id":"a","method":"apply"}`+"\n")
	_, _ = io.WriteString(raw, `{"jsonrpc":"2.0","method":"$/cancel","params":{"id":"a"}}`+"\n")
	m := readMsg(t, r)
	if m.Error == nil || m.Error.Code != CodeCancelled || string(m.ID) != `"a"` {
		t.Fatalf("%+v", m)
	}
}

// A broken connection during a long call (plugin crashed during apply).
func TestCloseDuringCall(t *testing.T) {
	started := make(chan struct{})
	ca, cb := pair(t, nil, func(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	errc := make(chan error, 1)
	go func() { errc <- ca.CallNoTimeout(context.Background(), "apply", nil, nil) }()
	<-started
	_ = cb.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call not released")
	}
	if err := ca.Call(context.Background(), "x", nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
}

func TestDefaultTimeoutAndNotify(t *testing.T) {
	got := make(chan string, 1)
	ca, _ := pair(t, nil, func(ctx context.Context, method string, p json.RawMessage) (any, error) {
		if method == "note" {
			got <- string(p)
			return nil, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err := ca.Notify("note", "x"); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v != `"x"` {
		t.Fatal(v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := ca.Call(ctx, "slow", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestHeartbeat(t *testing.T) {
	ca, _ := pair(t, nil, nil)
	alive := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var down atomic.Int32
	go ca.Heartbeat(ctx, 20*time.Millisecond, 3, func() { down.Add(1) }, func() { alive <- struct{}{} })
	time.Sleep(150 * time.Millisecond)
	if down.Load() != 0 {
		t.Fatal("answering peer reported as not responding")
	}

	// A peer that reads but never answers: pings time out.
	a, b := net.Pipe()
	defer b.Close()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	c := NewConn(a, nil, Options{})
	defer c.Close()
	stuck := make(chan struct{})
	go func() {
		c.Heartbeat(ctx, 20*time.Millisecond, 3, func() { close(stuck) }, nil)
	}()
	select {
	case <-stuck:
	case <-time.After(5 * time.Second):
		t.Fatal("unresponsive peer not detected")
	}
}

func TestBusy(t *testing.T) {
	block := make(chan struct{})
	a, b := net.Pipe()
	srv := NewConn(b, func(ctx context.Context, _ string, _ json.RawMessage) (any, error) {
		<-block
		return 1, nil
	}, Options{MaxInFlight: 1})
	cl := NewConn(a, nil, Options{})
	defer srv.Close()
	defer cl.Close()
	errc := make(chan error, 1)
	go func() { errc <- cl.Call(context.Background(), "a", nil, nil) }()
	time.Sleep(50 * time.Millisecond)
	if err := cl.Call(context.Background(), "b", nil, nil); !IsCode(err, CodeBusy) {
		t.Fatalf("err = %v", err)
	}
	close(block)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestOnClose(t *testing.T) {
	a, b := net.Pipe()
	reason := make(chan error, 1)
	c := NewConn(a, nil, Options{OnClose: func(err error) { reason <- err }})
	_ = b.Close()
	select {
	case err := <-reason:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("reason %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnClose not called")
	}
	_ = c.Close()
}

// A peer that stops reading cannot block writers forever.
func TestWriteTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewConn(a, nil, Options{WriteTimeout: 50 * time.Millisecond})
	defer c.Close()
	err := c.Notify("x", nil)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not closed")
	}
}
