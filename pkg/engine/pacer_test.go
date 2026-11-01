package engine

import (
	"testing"
	"time"
)

func TestParseSpeedMultiplier(t *testing.T) {
	tests := []struct {
		input       string
		expected    float64
		expectError bool
	}{
		{"1x", 1.0, false},
		{"1X", 1.0, false},
		{"2.5x", 2.5, false},
		{"0.5x", 0.5, false},
		{"10", 10.0, false},
		{"0", 0.0, false},
		{"max", 0.0, false},
		{"fast", 0.0, false},
		{"unthrottled", 0.0, false},
		{"", 0.0, false},
		{"-2x", 0.0, true},
		{"invalid", 0.0, true},
	}

	for _, tc := range tests {
		val, err := ParseSpeedMultiplier(tc.input)
		if tc.expectError && err == nil {
			t.Errorf("expected error for input %q, got nil", tc.input)
		}
		if !tc.expectError && err != nil {
			t.Errorf("unexpected error for input %q: %v", tc.input, err)
		}
		if !tc.expectError && val != tc.expected {
			t.Errorf("for input %q: expected %f, got %f", tc.input, tc.expected, val)
		}
	}
}

func TestReplayPacerPacing(t *testing.T) {
	// Replaying 2 packets with 60ms difference at 1.0x should take approx 60ms.
	pacer := NewReplayPacer(PacerConfig{
		SpeedMultiplier: 1.0,
		MaxDelay:        1 * time.Second,
	})

	stopChan := make(chan struct{})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(60 * time.Millisecond)

	startWall := time.Now()
	// First packet: no delay
	if err := pacer.Pace(stopChan, t0); err != nil {
		t.Fatalf("first packet pacing failed: %v", err)
	}

	// Second packet: 60ms delay
	if err := pacer.Pace(stopChan, t1); err != nil {
		t.Fatalf("second packet pacing failed: %v", err)
	}
	elapsed := time.Since(startWall)

	if elapsed < 45*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Errorf("expected elapsed time ~60ms at 1.0x, got %v", elapsed)
	}

	// Test 2x acceleration: 60ms delta at 2x should take ~30ms
	pacer.Reset()
	pacer.SetSpeed(2.0)
	startWall = time.Now()
	_ = pacer.Pace(stopChan, t0)
	_ = pacer.Pace(stopChan, t1)
	elapsed2x := time.Since(startWall)

	if elapsed2x < 20*time.Millisecond || elapsed2x > 60*time.Millisecond {
		t.Errorf("expected elapsed time ~30ms at 2.0x, got %v", elapsed2x)
	}

	// Test unthrottled (speed <= 0): should be almost instantaneous (< 10ms)
	pacer.Reset()
	pacer.SetSpeed(0.0)
	startWall = time.Now()
	_ = pacer.Pace(stopChan, t0)
	_ = pacer.Pace(stopChan, t1)
	elapsedUnthrottled := time.Since(startWall)

	if elapsedUnthrottled > 15*time.Millisecond {
		t.Errorf("expected instant elapsed time for unthrottled, got %v", elapsedUnthrottled)
	}
}

func TestReplayPacerMaxDelay(t *testing.T) {
	// 10 second capture delta capped by MaxDelay of 40ms
	pacer := NewReplayPacer(PacerConfig{
		SpeedMultiplier: 1.0,
		MaxDelay:        40 * time.Millisecond,
	})

	stopChan := make(chan struct{})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(10 * time.Second)

	start := time.Now()
	_ = pacer.Pace(stopChan, t0)
	_ = pacer.Pace(stopChan, t1)
	elapsed := time.Since(start)

	if elapsed < 30*time.Millisecond || elapsed > 100*time.Millisecond {
		t.Errorf("expected elapsed time capped near 40ms, got %v", elapsed)
	}
}

func TestReplayPacerStopInterrupt(t *testing.T) {
	pacer := NewReplayPacer(PacerConfig{
		SpeedMultiplier: 1.0,
		MaxDelay:        5 * time.Second,
	})

	stopChan := make(chan struct{})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Second)

	_ = pacer.Pace(stopChan, t0)

	go func() {
		time.Sleep(20 * time.Millisecond)
		close(stopChan)
	}()

	start := time.Now()
	err := pacer.Pace(stopChan, t1)
	elapsed := time.Since(start)

	if err != ErrPacingInterrupted {
		t.Errorf("expected ErrPacingInterrupted, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("stop did not interrupt promptly, elapsed: %v", elapsed)
	}
}

