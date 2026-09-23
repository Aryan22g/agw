package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Sink persists one decision and reports the record it wrote.
//
// Returning the record matters: the chain sequence is assigned here, and
// anything downstream -- a SIEM copy, an anomaly observer -- needs the real
// sequence to be reconcilable against the local evidence log. Returning only
// an error would leave every forwarded copy carrying seq 0.
type Sink interface {
	Write(ctx context.Context, eventName string, ev GatewayEvent) (Record, error)
}

// CheckpointSigner signs chain checkpoints.
type CheckpointSigner interface {
	Sign(message []byte) ([]byte, error)
	KeyID() string
}

// EvidenceSinkConfig configures the tamper-evident JSONL sink.
type EvidenceSinkConfig struct {
	Path string

	// Signer and KeyID sign periodic checkpoints. Without them the log is
	// still internally consistent, but it cannot be pinned to a point in
	// time: anyone able to rewrite the whole file could recompute every hash
	// and produce a consistent forgery.
	//
	// Taking a Signer rather than a raw key means checkpoints can be signed
	// by a key the gateway does not hold, so a compromise cannot forge
	// historical checkpoints even with full process access.
	Signer CheckpointSigner
	KeyID  string

	// CheckpointEvery commits to the chain head after this many records.
	// Defaults to 100.
	CheckpointEvery uint64

	// CheckpointInterval commits at least this often even when traffic is
	// light, so a quiet log still gets anchored. Defaults to 5 minutes.
	CheckpointInterval time.Duration
}

// EvidenceSink writes a hash-chained, checkpointed decision log.
//
// The chain is what makes the output evidence rather than a log file: an
// ordinary log can be edited or truncated by anyone with write access and no
// reader can tell. Here, altering or removing any record breaks every hash
// after it, and the break identifies exactly which record was touched.
type EvidenceSink struct {
	mu  sync.Mutex
	f   *os.File
	bw  *bufio.Writer
	enc *json.Encoder

	cfg EvidenceSinkConfig

	seq         uint64
	head        string
	sinceLastCP uint64
	lastCPAt    time.Time
	recordsAtCP uint64

	// syncMu serializes fsync, and syncedSeq records how far durability has
	// reached. Together they implement group commit: concurrent writers
	// append under mu, then one of them performs a single fsync that covers
	// every record appended so far, and the rest observe that their own
	// record is already durable and return.
	//
	// Holding mu across the fsync -- which is what this replaced -- made
	// concurrent requests queue behind one another's flushes, so 32 callers
	// each paid the latency of 32 serialized fsyncs. The durability guarantee
	// is unchanged: no caller returns until a sync covering its record has
	// completed.
	syncMu    sync.Mutex
	syncedSeq uint64

	// stopTicker ends the background checkpointer; tickerDone reports that
	// it has exited, so Close never races a checkpoint in flight.
	// cpErr is the most recent checkpoint failure, nil once one succeeds.
	cpErr     error
	cpRetryAt time.Time

	stopTicker chan struct{}
	tickerDone chan struct{}
	closeOnce  sync.Once
}

// NewEvidenceSink opens or resumes a chained log at cfg.Path.
//
// Resuming matters: a restart must continue the existing chain rather than
// starting a new one, or every restart would silently create a seam an
// auditor cannot distinguish from tampering.
func NewEvidenceSink(cfg EvidenceSinkConfig) (*EvidenceSink, error) {
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = 100
	}
	if cfg.CheckpointInterval == 0 {
		cfg.CheckpointInterval = 5 * time.Minute
	}

	seq, head, err := resumeChain(cfg.Path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open evidence log: %w", err)
	}

	bw := bufio.NewWriterSize(f, 64<<10)

	sink := &EvidenceSink{
		f:           f,
		bw:          bw,
		enc:         json.NewEncoder(bw),
		cfg:         cfg,
		seq:         seq,
		head:        head,
		lastCPAt:    time.Now().UTC(),
		recordsAtCP: seq,
	}

	// A quiet log still gets anchored. CheckpointInterval was documented as
	// "commits at least this often even when traffic is light", but it was
	// only consulted inside Write -- so after the last record the tail stayed
	// unsigned until more traffic arrived or the process stopped, and the
	// tail is exactly what an attacker can remove without trace. A ticker
	// makes the documented guarantee true.
	if cfg.Signer != nil {
		sink.stopTicker = make(chan struct{})
		sink.tickerDone = make(chan struct{})
		go sink.checkpointLoop()
	}
	return sink, nil
}

// checkpointLoop writes a checkpoint every CheckpointInterval while there
// are records it would cover.
func (s *EvidenceSink) checkpointLoop() {
	defer close(s.tickerDone)
	t := time.NewTicker(s.cfg.CheckpointInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopTicker:
			return
		case <-t.C:
			// Errors surface on the next Write or at Close, both of which
			// checkpoint too; a background goroutine has nobody to tell.
			_ = s.Checkpoint()
		}
	}
}

// checkpointRetryBackoff spaces write-path retries after a failed checkpoint.
const checkpointRetryBackoff = 5 * time.Second

// CheckpointError reports why the most recent checkpoint could not be
// written, or nil. Records keep being written while it is non-nil; they are
// chained but not anchored, and an operator needs to know that.
func (s *EvidenceSink) CheckpointError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cpErr
}

// SignedThrough reports the sequence the latest checkpoint covers. Records
// after it are chained but not yet anchored.
func (s *EvidenceSink) SignedThrough() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordsAtCP
}

// resumeChain reads an existing log to recover the sequence and head hash.
func resumeChain(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, GenesisHash, nil
		}
		return 0, "", fmt.Errorf("read evidence log: %w", err)
	}
	defer f.Close()

	var (
		seq  uint64
		head = GenesisHash
	)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		rec, _, err := decodeLine(raw)
		if err != nil {
			return 0, "", fmt.Errorf("evidence log is corrupt at record %d: %w", seq+1, err)
		}
		if rec == nil {
			continue // checkpoint line
		}
		seq = rec.Seq
		head = rec.Hash
	}
	if err := scanner.Err(); err != nil {
		return 0, "", fmt.Errorf("scan evidence log: %w", err)
	}

	return seq, head, nil
}

// Write appends one chained decision record, and a checkpoint when due.
func (s *EvidenceSink) Write(ctx context.Context, eventName string, ev GatewayEvent) (Record, error) {
	_ = ctx

	s.mu.Lock()

	rec := Link(Record{
		EventName: eventName,
		Timestamp: time.Now().UTC(),
		Event:     ev,
	}, s.seq+1, s.head)

	if err := s.enc.Encode(&rec); err != nil {
		s.mu.Unlock()
		return Record{}, fmt.Errorf("write evidence record: %w", err)
	}

	s.seq = rec.Seq
	s.head = rec.Hash
	s.sinceLastCP++

	// A checkpoint that cannot be signed does not un-write the record: the
	// record is already appended and, after the sync below, durable. Failing
	// the Write here -- what this used to do -- told a fail-closed caller the
	// decision was not recorded, so it refused the action while the chain
	// said the action was allowed; and when the signer was a daemon that
	// refused checkpoints, it refused every request once a checkpoint fell
	// due. The failure is kept for CheckpointError, and the next write or
	// the interval ticker retries it.
	if s.checkpointDue() {
		s.cpErr = s.writeCheckpointLocked()
		if s.cpErr != nil {
			s.cpRetryAt = time.Now().Add(checkpointRetryBackoff)
		}
	}
	s.mu.Unlock()

	// Durability before reporting success. The gateway refuses to forward a
	// request whose decision could not be recorded, so "recorded" has to mean
	// durably on disk rather than sitting in a buffer a crash would discard.
	if err := s.syncThrough(rec.Seq); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// syncThrough returns once a sync covering seq has completed.
//
// The first caller to arrive performs the flush and fsync for everyone;
// callers whose records were already covered by an in-flight sync return
// without issuing another. Concurrency therefore improves throughput rather
// than multiplying fsyncs, while every caller still waits for real durability.
func (s *EvidenceSink) syncThrough(seq uint64) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	if s.syncedSeq >= seq {
		return nil
	}

	s.mu.Lock()
	target := s.seq
	err := s.bw.Flush()
	s.mu.Unlock()

	if err != nil {
		return fmt.Errorf("flush evidence log: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("sync evidence log: %w", err)
	}

	s.syncedSeq = target
	return nil
}

func (s *EvidenceSink) checkpointDue() bool {
	if s.cfg.Signer == nil {
		return false
	}
	// After a failed checkpoint, wait before trying again from the write
	// path. Retrying on every write would hold the sink lock across a
	// signer timeout for every request while a signing daemon is down; the
	// interval ticker keeps retrying regardless.
	if s.cpErr != nil && time.Now().Before(s.cpRetryAt) {
		return false
	}
	if s.sinceLastCP >= s.cfg.CheckpointEvery {
		return true
	}
	return time.Since(s.lastCPAt) >= s.cfg.CheckpointInterval
}

func (s *EvidenceSink) writeCheckpointLocked() error {
	cp, err := SignCheckpointWith(s.cfg.Signer, s.cfg.KeyID, s.seq, s.head, s.seq, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign checkpoint: %w", err)
	}
	if err := s.enc.Encode(cp); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}

	s.sinceLastCP = 0
	s.lastCPAt = time.Now().UTC()
	s.recordsAtCP = s.seq
	return nil
}

// Checkpoint forces a checkpoint, used on shutdown so the final records are
// anchored rather than left after the last signature.
func (s *EvidenceSink) Checkpoint() error {
	s.mu.Lock()

	if s.cfg.Signer == nil || s.sinceLastCP == 0 {
		s.mu.Unlock()
		return nil
	}
	if err := s.writeCheckpointLocked(); err != nil {
		s.cpErr = err
		s.mu.Unlock()
		return err
	}
	s.cpErr = nil
	target := s.seq
	err := s.bw.Flush()
	s.mu.Unlock()

	if err != nil {
		return fmt.Errorf("flush evidence log: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return err
	}

	s.syncMu.Lock()
	if target > s.syncedSeq {
		s.syncedSeq = target
	}
	s.syncMu.Unlock()
	return nil
}

// Head reports the current sequence and chain hash.
func (s *EvidenceSink) Head() (uint64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq, s.head
}

// Close writes a final checkpoint and closes the file.
func (s *EvidenceSink) Close() error {
	s.closeOnce.Do(func() {
		if s.stopTicker != nil {
			close(s.stopTicker)
			<-s.tickerDone
		}
	})
	if err := s.Checkpoint(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.bw.Flush(); err != nil {
		return fmt.Errorf("flush evidence log: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	return s.f.Close()
}

// NewJSONLSink opens an unsigned chained log.
//
// Retained for deployments that have not yet been given a checkpoint key. The
// chain still detects edits, but without checkpoints it cannot resist a
// wholesale rewrite, so this is a weaker guarantee and should not be the
// configuration a compliance claim rests on.
func NewJSONLSink(path string) (*EvidenceSink, error) {
	return NewEvidenceSink(EvidenceSinkConfig{Path: path})
}
