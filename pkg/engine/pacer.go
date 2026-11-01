package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrPacingInterrupted is returned when pacing is interrupted by engine shutdown.
	ErrPacingInterrupted = errors.New("replay pacing interrupted")
)

// PacerConfig defines timing behavior for PCAP playback rate regulation.
type PacerConfig struct {
	// SpeedMultiplier is the playback speed factor (e.g., 1.0 = realtime, 2.0 = 2x, 0.5 = half speed).
	// Values <= 0 indicate unthrottled maximum speed.
	SpeedMultiplier float64

	// MaxDelay caps the maximum pause between packets (e.g., 5 seconds) so large capture idle gaps do not freeze replay.
	// 0 or negative values disable delay capping.
	MaxDelay time.Duration
}

// ParseSpeedMultiplier parses user-supplied strings like "1x", "2X", "0.5", "10", "max", "unthrottled".
func ParseSpeedMultiplier(s string) (float64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "max" || s == "fast" || s == "unthrottled" {
		return 0.0, nil
	}

	cleaned := strings.TrimSuffix(s, "x")
	val, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid speed format %q: expected e.g. '1x', '2.5', '10x', or 'max'", s)
	}
	if val < 0 {
		return 0, fmt.Errorf("replay speed must be non-negative: %f", val)
	}
	return val, nil
}

// ReplayPacer regulates the packet ingestion rate relative to original pcap timestamps.
type ReplayPacer struct {
	mu           sync.Mutex
	cfg          PacerConfig
	firstPacket  bool
	lastPktTime  time.Time
	lastWallTime time.Time
}

// NewReplayPacer creates a new PCAP replay rate controller.
func NewReplayPacer(cfg PacerConfig) *ReplayPacer {
	return &ReplayPacer{
		cfg:         cfg,
		firstPacket: true,
	}
}

// Pace calculates and applies the proportional sleep duration before processing pktTime.
// If stopChan is closed or receives a value, Pace aborts immediately.
func (p *ReplayPacer) Pace(stopChan <-chan struct{}, pktTime time.Time) error {
	p.mu.Lock()
	speed := p.cfg.SpeedMultiplier
	maxDelay := p.cfg.MaxDelay
	isFirst := p.firstPacket
	lastPkt := p.lastPktTime
	lastWall := p.lastWallTime
	p.mu.Unlock()

	// Unthrottled / fast forward
	if speed <= 0 {
		return nil
	}

	now := time.Now()

	// Initial packet sets reference point
	if isFirst {
		p.mu.Lock()
		p.firstPacket = false
		p.lastPktTime = pktTime
		p.lastWallTime = now
		p.mu.Unlock()
		return nil
	}

	pktDelta := pktTime.Sub(lastPkt)
	if pktDelta <= 0 {
		// Out of order or zero delta timestamp in capture, do not delay
		p.mu.Lock()
		p.lastPktTime = pktTime
		p.lastWallTime = now
		p.mu.Unlock()
		return nil
	}

	targetDelay := time.Duration(float64(pktDelta) / speed)
	if maxDelay > 0 && targetDelay > maxDelay {
		targetDelay = maxDelay
	}

	// Compensate for Go engine processing time spent since previous packet
	elapsedSinceLast := now.Sub(lastWall)
	sleepDuration := targetDelay - elapsedSinceLast

	if sleepDuration > 0 {
		timer := time.NewTimer(sleepDuration)
		select {
		case <-stopChan:
			timer.Stop()
			return ErrPacingInterrupted
		case <-timer.C:
		}
	}

	p.mu.Lock()
	p.lastPktTime = pktTime
	p.lastWallTime = time.Now()
	p.mu.Unlock()

	return nil
}

// SetSpeed dynamically updates the replay speed multiplier.
func (p *ReplayPacer) SetSpeed(speed float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.SpeedMultiplier = speed
}

// GetSpeed returns the current speed multiplier.
func (p *ReplayPacer) GetSpeed() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.SpeedMultiplier
}

// Reset clears state so the pacer can be reused for another run.
func (p *ReplayPacer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.firstPacket = true
	p.lastPktTime = time.Time{}
	p.lastWallTime = time.Time{}
}

