package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNoSink = errors.New("audit sink is nil")

type Service struct {
	sink Sink
}

func NewService(sink Sink) *Service {
	return &Service{sink: sink}
}

// Log durably writes the event before any side effect that depends on it, and
// returns the record as written, including its chain sequence.
func (s *Service) Log(ctx context.Context, eventName string, ev GatewayEvent) (Record, error) {
	if s == nil || s.sink == nil {
		return Record{}, ErrNoSink
	}

	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("evt_%d", time.Now().UTC().UnixNano())
	}
	if ev.FinishedAt.IsZero() && !ev.StartedAt.IsZero() {
		ev.FinishedAt = time.Now().UTC()
		ev.LatencyMS = ev.FinishedAt.Sub(ev.StartedAt).Milliseconds()
	}

	return s.sink.Write(ctx, eventName, ev)
}
