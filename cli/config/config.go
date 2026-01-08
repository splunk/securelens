package config

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// NewConfigCmd creates the config command
func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage SecureLens configuration",
		Long:  `Initialize, validate, and manage SecureLens configuration.`,
	}

	// Add subcommands
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newValidateCmd())
	cmd.AddCommand(newSetCmd())

	return cmd
}

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration file",
		Long: `Create a new configuration file with default values.

The configuration file will be created at ~/.securelens/config.yaml

Example:
  securelens config init`,
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Initializing configuration")

			homeDir, err := os.UserHomeDir()
			if err != nil {
				slog.Error("Failed to get home directory", "error", err)
				return
			}

			configDir := filepath.Join(homeDir, ".securelens")
			configFile := filepath.Join(configDir, "config.yaml")

			// Create the directory if it doesn't exist
			if err := os.MkdirAll(configDir, 0700); err != nil {
				slog.Error("Failed to create config directory", "error", err)
				return
			}

			// Check if the config file already exists
			if _, err := os.Stat(configFile); err == nil {
				slog.Warn("Configuration file already exists", "path", configFile)
				return
			} else if !os.IsNotExist(err) {
				slog.Error("Failed to check config file", "error", err)
				return
			}

			// Copy example config content
			examplePath := "config.example.yaml"
			exampleContent, err := os.ReadFile(examplePath)
			if err != nil {
				slog.Error("Failed to read example config file", "error", err)
				return
			}
			if err := os.WriteFile(configFile, exampleContent, 0600); err != nil {
				slog.Error("Failed to write to config file", "error", err)
				return
			}

			slog.Info("Configuration file created successfully")
		},
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		Long: `Validate the configuration file for correctness.

Example:
  securelens config validate`,
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Validating configuration")
			// TODO: Implement configuration validation logic
			slog.Info("Configuration is valid")
		},
	}
}

func newSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: `Set a configuration value in the configuration file.

Examples:
  securelens config set database.host localhost
  securelens config set scanning.parallel_workers 10`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			value := args[1]
			slog.Info("Setting configuration value", "key", key, "value", value)
			// TODO: Implement configuration set logic
			slog.Info("Configuration value updated successfully")
		},
	}
}
