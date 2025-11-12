package main

import (
	"log/slog"
	"os"

	"github.com/splunk/securelens/cmd/securelens"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Execute root command
	if err := securelens.Execute(); err != nil {
		slog.Error("Failed to execute command", "error", err)
		os.Exit(1)
	}
}
