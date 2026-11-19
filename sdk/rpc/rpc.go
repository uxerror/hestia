// Package rpc is a bidirectional JSON-RPC 2.0 connection over a byte stream.
// Every message is one line of JSON terminated by "\n" (NDJSON). Both sides
// may send requests, responses and notifications; request ids are numbered
// by each side independently. A request is cancelled with the notification
// "$/cancel" {"id": <id>}. Both the Hestia controller and plugins (through
// package sdk) use this code. Only the standard library is used.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// MaxLine is the longest message (one line, without the newline) a
// connection accepts or sends. A longer incoming line breaks the connection.
const MaxLine = 8 << 20

// DefaultTimeout bounds Call when the context has no deadline.
const DefaultTimeout = 30 * time.Second

// Heartbeat defaults: a "ping" every 30 s, three misses in a row mean the
// peer is not responding.
const (
	HeartbeatInterval = 30 * time.Second
	HeartbeatMisses   = 3
)

// Methods with a meaning on the protocol level.
const (
	MethodCancel = "$/cancel"
	MethodPing   = "ping"
)

// Standard and Hestia-specific error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	// CodePermission: the caller lacks a permission or a grant.
	CodePermission = -32001
	// CodeProtocol: unsupported protocol version or a failed handshake.
	CodeProtocol = -32002
	// CodeCancelled: the request was cancelled with $/cancel.
	CodeCancelled = -32800
	// CodeBusy: too many requests in flight.
	CodeBusy = -32003
)

// Error is a JSON-RPC error object. A handler may return *Error to control
// the code; any other error becomes CodeInternal with err.Error().
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Errorf builds an *Error.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IsCode reports whether err is an *Error with the given code.
func IsCode(err error, code int) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Sentinel errors of a connection.
var (
	// ErrClosed is returned for calls on (or pending at) a closed connection.
	ErrClosed = errors.New("соединение закрыто")
	// ErrLineTooLong means a message exceeded MaxLine.
	ErrLineTooLong = errors.New("сообщение длиннее 8 МБ")
)

// Message is one JSON-RPC message on the wire.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Handler serves an incoming request or notification. For notifications the
// result is discarded. ctx is cancelled by "$/cancel" or when the
// connection closes.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, error)

// Options tune a connection.
type Options struct {
	// MaxInFlight bounds concurrently served incoming requests (default 64).
	MaxInFlight int
	// WriteTimeout bounds one write when the transport supports deadlines
	// (net.Conn); a peer that stops reading breaks the connection
	// (default DefaultTimeout).
	WriteTimeout time.Duration
	// OnClose is called once when the connection is closed, with the reason
	// (nil for a local Close).
	OnClose func(err error)
}

// Conn is one side of a connection.
type Conn struct {
	rwc     io.ReadWriteCloser
	handler Handler
	opts    Options

	wmu       sync.Mutex // serialises writes
	startOnce sync.Once

	mu       sync.Mutex
	nextID   int64
	pending  map[string]chan *Message
	serving  map[string]context.CancelFunc
	closed   bool
	closeErr error

	done     chan struct{}
	ctx      context.Context // cancelled on close: parent of handler contexts
	cancel   context.CancelFunc
	inflight chan struct{}
}

// NewConn wraps rwc and starts reading. h may be nil (every request gets
// "method not found"); "ping" is always answered.
func NewConn(rwc io.ReadWriteCloser, h Handler, opts Options) *Conn {
	c := New(rwc, h, opts)
	c.Start()
	return c
}

// New wraps rwc without reading yet: call Start once the handler's own
// state refers to the connection.
func New(rwc io.ReadWriteCloser, h Handler, opts Options) *Conn {
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = 64
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = DefaultTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		rwc: rwc, handler: h, opts: opts,
		pending: map[string]chan *Message{}, serving: map[string]context.CancelFunc{},
		done: make(chan struct{}), ctx: ctx, cancel: cancel,
		inflight: make(chan struct{}, opts.MaxInFlight),
	}
	return c
}

// Start begins reading messages (once).
func (c *Conn) Start() { c.startOnce.Do(func() { go c.readLoop() }) }

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the connection closed (nil while open or after Close).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// Close closes the connection; pending calls fail with ErrClosed.
func (c *Conn) Close() error {
	c.shutdown(nil)
	return nil
}

func (c *Conn) shutdown(reason error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = reason
	pending := c.pending
	c.pending = map[string]chan *Message{}
	c.mu.Unlock()

	c.cancel()
	_ = c.rwc.Close()
	for _, ch := range pending {
		close(ch)
	}
	close(c.done)
	if c.opts.OnClose != nil {
		c.opts.OnClose(reason)
	}
}

func (c *Conn) readLoop() {
	sc := bufio.NewScanner(c.rwc)
	sc.Buffer(make([]byte, 64<<10), MaxLine+1)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxLine {
			c.shutdown(ErrLineTooLong)
			return
		}
		c.dispatch(line)
	}
	err := sc.Err()
	switch {
	case errors.Is(err, bufio.ErrTooLong):
		err = ErrLineTooLong
	case err == nil:
		err = io.EOF
	}
	c.shutdown(err)
}

func (c *Conn) dispatch(line []byte) {
	var m Message
	if err := json.Unmarshal(line, &m); err != nil || m.JSONRPC != "2.0" {
		// A broken message: answer with a parse error (id unknown).
		// Replies are written off the reader goroutine: with an unbuffered
		// transport two readers writing to each other would deadlock.
		go func() {
			_ = c.send(&Message{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &Error{Code: CodeParseError, Message: "некорректное сообщение JSON-RPC"}})
		}()
		return
	}
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	switch {
	case m.Method != "" && hasID:
		c.serve(&m)
	case m.Method != "":
		c.notification(&m)
	case hasID:
		c.mu.Lock()
		ch, ok := c.pending[string(m.ID)]
		delete(c.pending, string(m.ID))
		c.mu.Unlock()
		if ok {
			ch <- &m
		}
	}
}

func (c *Conn) notification(m *Message) {
	if m.Method == MethodCancel {
		var p struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			c.mu.Lock()
			cancel := c.serving[string(p.ID)]
			c.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
		return
	}
	if c.handler != nil {
		// Notifications are served in order on the reader goroutine; handlers
		// must be quick.
		_, _ = c.handler(c.ctx, m.Method, m.Params)
	}
}

func (c *Conn) serve(m *Message) {
	if m.Method == MethodPing {
		go func() { _ = c.reply(m.ID, struct{}{}, nil) }()
		return
	}
	select {
	case c.inflight <- struct{}{}:
	default:
		go func() {
			_ = c.reply(m.ID, nil, Errorf(CodeBusy, "слишком много одновременных запросов"))
		}()
		return
	}
	ctx, cancel := context.WithCancel(c.ctx)
	key := string(m.ID)
	c.mu.Lock()
	c.serving[key] = cancel
	c.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			c.mu.Lock()
			delete(c.serving, key)
			c.mu.Unlock()
			<-c.inflight
		}()
		var (
			res any
			err error
		)
		if c.handler == nil {
			err = Errorf(CodeMethodNotFound, "метод %s не поддерживается", m.Method)
		} else {
			res, err = safeHandle(ctx, c.handler, m.Method, m.Params)
		}
		if err != nil && ctx.Err() != nil && c.ctx.Err() == nil && !IsCode(err, CodeCancelled) {
			err = Errorf(CodeCancelled, "запрос отменён")
		}
		_ = c.reply(m.ID, res, err)
	}()
}

func safeHandle(ctx context.Context, h Handler, method string, params json.RawMessage) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = Errorf(CodeInternal, "паника в обработчике %s: %v", method, p)
		}
	}()
	return h(ctx, method, params)
}

func (c *Conn) reply(id json.RawMessage, res any, err error) error {
	m := &Message{JSONRPC: "2.0", ID: id}
	if err != nil {
		var re *Error
		if !errors.As(err, &re) {
			re = &Error{Code: CodeInternal, Message: err.Error()}
		}
		m.Error = re
	} else {
		b, merr := json.Marshal(res)
		if merr != nil {
			m.Error = &Error{Code: CodeInternal, Message: "ответ не сериализуется: " + merr.Error()}
		} else {
			m.Result = b
		}
	}
	err = c.send(m)
	if errors.Is(err, ErrLineTooLong) {
		// Tell the caller instead of leaving it waiting.
		m.Result, m.Error = nil, &Error{Code: CodeInternal, Message: "ответ длиннее 8 МБ"}
		return c.send(m)
	}
	return err
}

func (c *Conn) send(m *Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxLine {
		return ErrLineTooLong
	}
	b = append(b, '\n')
	c.wmu.Lock()
	defer c.wmu.Unlock()
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	if d, ok := c.rwc.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(c.opts.WriteTimeout))
	}
	if _, err := c.rwc.Write(b); err != nil {
		go c.shutdown(err)
		return ErrClosed
	}
	return nil
}

// Notify sends a notification.
func (c *Conn) Notify(method string, params any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	return c.send(&Message{JSONRPC: "2.0", Method: method, Params: p})
}

// Call sends a request and decodes the result into result (may be nil).
// Without a deadline in ctx DefaultTimeout applies. When ctx ends first the
// peer receives "$/cancel".
func (c *Conn) Call(ctx context.Context, method string, params, result any) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	return c.CallNoTimeout(ctx, method, params, result)
}

// CallNoTimeout is Call without the default timeout: it waits until the
// answer, the end of ctx or the end of the connection.
func (c *Conn) CallNoTimeout(ctx context.Context, method string, params, result any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	ch := make(chan *Message, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.nextID++
	id := json.RawMessage(strconv.FormatInt(c.nextID, 10))
	c.pending[string(id)] = ch
	c.mu.Unlock()

	if err := c.send(&Message{JSONRPC: "2.0", ID: id, Method: method, Params: p}); err != nil {
		c.mu.Lock()
		delete(c.pending, string(id))
		c.mu.Unlock()
		return err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if m.Error != nil {
			return m.Error
		}
		if result != nil && len(m.Result) > 0 {
			if err := json.Unmarshal(m.Result, result); err != nil {
				return fmt.Errorf("ответ %s: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, string(id))
		c.mu.Unlock()
		_ = c.Notify(MethodCancel, map[string]json.RawMessage{"id": id})
		return ctx.Err()
	case <-c.done:
		return ErrClosed
	}
}

func marshalParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	if raw, ok := params.(json.RawMessage); ok {
		return raw, nil
	}
	return json.Marshal(params)
}

// Heartbeat pings the peer every interval (each ping bounded by interval)
// until ctx ends or the connection closes. After misses failed pings in a
// row it calls onUnresponsive once; a later successful ping calls onAlive.
// Either callback may be nil.
func (c *Conn) Heartbeat(ctx context.Context, interval time.Duration, misses int, onUnresponsive, onAlive func()) {
	if interval <= 0 {
		interval = HeartbeatInterval
	}
	if misses <= 0 {
		misses = HeartbeatMisses
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, interval)
		err := c.Call(pctx, MethodPing, nil, nil)
		cancel()
		if err == nil {
			if failed >= misses && onAlive != nil {
				onAlive()
			}
			failed = 0
			continue
		}
		if errors.Is(err, ErrClosed) {
			return
		}
		failed++
		if failed == misses && onUnresponsive != nil {
			onUnresponsive()
		}
	}
}
