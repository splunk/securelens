package securelens

import (
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/splunk/securelens/cli/config"
	"github.com/splunk/securelens/cli/ingest"
	"github.com/splunk/securelens/cli/query"
	"github.com/splunk/securelens/cli/scan"
	"github.com/splunk/securelens/cli/ui"
)

var (
	cfgFile string
	verbose bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "securelens",
	Short: "SecureLens Open Source - CLI-based vulnerability management framework",
	Long: `SecureLens Open Source is a CLI-based vulnerability management framework
designed to democratize enterprise-grade security scanning for the open source community.

Built upon the lessons learned from Splunk's internal SecureLens platform, this project
provides a streamlined, organization-agnostic tool for aggregating, deduplicating, and
tracking security vulnerabilities across multiple repositories and scanning tools.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set log level based on verbose flag
		if verbose {
			slog.SetLogLoggerLevel(slog.LevelDebug)
			slog.Debug("Verbose logging enabled")
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.securelens/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(scan.NewScanCmd())
	rootCmd.AddCommand(query.NewQueryCmd())
	rootCmd.AddCommand(config.NewConfigCmd())
	rootCmd.AddCommand(ui.NewUICmd())
	rootCmd.AddCommand(ingest.NewIngestCmd())
}
