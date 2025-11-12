package query

import (
	"log/slog"

	"github.com/spf13/cobra"
)

// NewQueryCmd creates the query command
func NewQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query vulnerability data",
		Long:  `Query and filter vulnerability data from the database.`,
	}

	// Add subcommands
	cmd.AddCommand(newVulnsCmd())
	cmd.AddCommand(newOwnersCmd())

	return cmd
}

func newVulnsCmd() *cobra.Command {
	var (
		severity   []string
		scanner    string
		repository string
		branch     string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "vulns",
		Short: "Query vulnerabilities",
		Long: `Search and filter vulnerabilities from the database.

Examples:
  securelens query vulns
  securelens query vulns --severity critical,high
  securelens query vulns --repo myorg/myrepo --branch main
  securelens query vulns --format json > vulnerabilities.json`,
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Querying vulnerabilities",
				"severity", severity,
				"scanner", scanner,
				"repository", repository,
				"branch", branch,
				"format", format,
			)
			// TODO: Implement vulnerability query logic
			slog.Info("Query completed successfully")
		},
	}

	cmd.Flags().StringSliceVar(&severity, "severity", nil, "filter by severity (critical,high,medium,low)")
	cmd.Flags().StringVar(&scanner, "scanner", "", "filter by scanner (semgrep,fossa,trufflehog)")
	cmd.Flags().StringVar(&repository, "repo", "", "filter by repository")
	cmd.Flags().StringVar(&branch, "branch", "", "filter by branch")
	cmd.Flags().StringVar(&format, "format", "table", "output format (table,json,csv,sarif)")

	return cmd
}

func newOwnersCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "owners",
		Short: "Query ownership mappings",
		Long: `View ownership mappings for repositories.

Examples:
  securelens query owners
  securelens query owners --format json`,
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Querying ownership mappings", "format", format)
			// TODO: Implement ownership query logic
			slog.Info("Query completed successfully")
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "output format (table,json,csv)")

	return cmd
}
