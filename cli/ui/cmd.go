package ui

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/splunk/securelens/internal/config"
)

// NewUICmd creates the ui-mode command
func NewUICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ui",
		Aliases: []string{"ui-mode", "tui"},
		Short:   "Launch interactive Terminal UI",
		Long: `Launch the SecureLens interactive Terminal UI for browsing repositories,
running scans, and viewing results.

Features:
  - Browse and search discovered repositories
  - Multi-select repos for bulk scanning
  - View scan results with drill-down
  - Add new provider credentials

Navigation:
  - Use arrow keys or j/k to navigate
  - Press ? for help
  - Press q to quit`,
		RunE: runUI,
	}

	return cmd
}

func runUI(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		slog.Warn("Failed to load config, continuing with defaults", "error", err)
		cfg = &config.Config{}
	}

	// Redirect slog to a file during TUI mode to prevent logs from interfering
	// with the alternate screen display
	logFile, err := os.CreateTemp("", "securelens-tui-*.log")
	if err != nil {
		// If we can't create a log file, discard logs instead
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	} else {
		defer logFile.Close()
		slog.SetDefault(slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
		// Store log file path for later reference
		defer func() {
			// Print log file location after TUI exits (useful for debugging)
			if stat, _ := logFile.Stat(); stat != nil && stat.Size() > 0 {
				fmt.Fprintf(os.Stderr, "TUI logs written to: %s\n", logFile.Name())
			}
		}()
	}

	// Create the model
	m := New(cfg)

	// Create the program
	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Run the program
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	// Check for any errors in the final model
	if fm, ok := finalModel.(Model); ok && fm.err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", fm.err)
	}

	return nil
}
