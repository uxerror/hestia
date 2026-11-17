package jobs

import "sync"

// Event is a message published to job subscribers. Type is "step", "log" or
// "status"; Data is JSON-serialisable.
type Event struct {
	Type string
	Data any
}

const subBuffer = 256

// Hub fans job events out to SSE subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan Event]struct{}
}

// NewHub creates an empty hub.
func NewHub() *Hub { return &Hub{subs: map[string]map[chan Event]struct{}{}} }

// Subscribe returns a channel of events for a job and a cancel func. If the
// subscriber falls behind, the channel is closed and it must resynchronise
// from the database.
func (h *Hub) Subscribe(jobID string) (<-chan Event, func()) {
	ch := make(chan Event, subBuffer)
	h.mu.Lock()
	if h.subs[jobID] == nil {
		h.subs[jobID] = map[chan Event]struct{}{}
	}
	h.subs[jobID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() { h.remove(jobID, ch) }
}

func (h *Hub) remove(jobID string, ch chan Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.subs[jobID]; set != nil {
		if _, ok := set[ch]; ok {
			delete(set, ch)
			close(ch)
		}
		if len(set) == 0 {
			delete(h.subs, jobID)
		}
	}
}

// Publish delivers an event to all subscribers of a job without blocking;
// slow subscribers are dropped (their channel is closed).
func (h *Hub) Publish(jobID string, ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[jobID] {
		select {
		case ch <- ev:
		default:
			delete(h.subs[jobID], ch)
			close(ch)
		}
	}
}
