package ui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	ColorPrimary   = lipgloss.Color("#7C3AED") // Purple
	ColorSecondary = lipgloss.Color("#06B6D4") // Cyan
	ColorSuccess   = lipgloss.Color("#10B981") // Green
	ColorWarning   = lipgloss.Color("#F59E0B") // Amber
	ColorError     = lipgloss.Color("#EF4444") // Red
	ColorMuted     = lipgloss.Color("#6B7280") // Gray
	ColorBorder    = lipgloss.Color("#374151") // Dark gray
)

// Provider colors
var (
	ColorGitHub    = lipgloss.Color("#238636")
	ColorGitLab    = lipgloss.Color("#FC6D26")
	ColorBitbucket = lipgloss.Color("#0052CC")
)

// Severity colors
var (
	ColorCritical = lipgloss.Color("#DC2626")
	ColorHigh     = lipgloss.Color("#EA580C")
	ColorMedium   = lipgloss.Color("#D97706")
	ColorLow      = lipgloss.Color("#2563EB")
	ColorInfo     = lipgloss.Color("#6B7280")
)

// Base styles
var (
	// App title
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(ColorPrimary).
			Padding(0, 1)

	// Subtle text
	SubtleStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// Help text
	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Italic(true)

	// Error text
	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	// Success text
	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess)

	// Warning text
	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning)

	// Border box
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2)

	// Selected item
	SelectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(ColorPrimary).
			Bold(true)

	// Active tab
	ActiveTabStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true).
			Underline(true)

	// Inactive tab
	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(ColorMuted)

	// Header
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(ColorPrimary).
			Padding(0, 1).
			MarginBottom(1)

	// Footer
	FooterStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1)

	// Status indicators
	StatusCompleteStyle = lipgloss.NewStyle().
				Foreground(ColorSuccess).
				Bold(true)

	StatusRunningStyle = lipgloss.NewStyle().
				Foreground(ColorSecondary)

	StatusErrorStyle = lipgloss.NewStyle().
				Foreground(ColorError).
				Bold(true)

	StatusPendingStyle = lipgloss.NewStyle().
				Foreground(ColorMuted)
)

// Provider badge styles
func ProviderStyle(provider string) lipgloss.Style {
	var color lipgloss.Color
	switch provider {
	case "github":
		color = ColorGitHub
	case "gitlab":
		color = ColorGitLab
	case "bitbucket":
		color = ColorBitbucket
	default:
		color = ColorMuted
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(color).
		Padding(0, 1)
}

// Severity badge styles
func SeverityStyle(severity string) lipgloss.Style {
	var color lipgloss.Color
	switch severity {
	case "CRITICAL":
		color = ColorCritical
	case "HIGH", "ERROR":
		color = ColorHigh
	case "MEDIUM", "WARNING":
		color = ColorMedium
	case "LOW":
		color = ColorLow
	default:
		color = ColorInfo
	}
	return lipgloss.NewStyle().
		Foreground(color).
		Bold(true)
}
