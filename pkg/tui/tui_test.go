package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
)

func TestTUIResponsiveDimensions(t *testing.T) {
	eng := &engine.Engine{}
	m := NewModel(eng, "eth0")

	// Set sample cached stats
	m.cachedStats = engine.Stats{
		TotalPackets: 100,
		TotalBytes:   10240,
		StartTime:    time.Now().Add(-10 * time.Minute),
		ProtocolCounts: map[string]uint64{
			"TCP": 80,
			"UDP": 20,
		},
		TopTalkersBytes: map[string]uint64{
			"192.168.1.100": 8000,
		},
	}

	widths := []int{0, 20, 40, 60, 80, 100, 160}

	for _, w := range widths {
		msg := tea.WindowSizeMsg{
			Width:  w,
			Height: 24,
		}
		updated, _ := m.Update(msg)
		model := updated.(Model)

		// Render View - must not panic
		view := model.View()
		if len(view) == 0 {
			t.Errorf("expected non-empty view for width %d", w)
		}

		// Ensure no raw negative dimensions leak into render
		if strings.Contains(view, "width: -") {
			t.Errorf("detected negative width style for width %d", w)
		}
	}
}
