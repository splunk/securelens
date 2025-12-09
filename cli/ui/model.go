package ui

import (
	"context"
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/splunk/securelens/cli/scan"
	"github.com/splunk/securelens/internal/config"
)

// Model is the root TUI model
type Model struct {
	// Current view
	view ViewType

	// Configuration
	config   *config.Config
	scanMode string // "standalone" or "remote" (auto-detected)

	// Data
	repos    []scan.DiscoveredRepository
	selected map[int]bool // multi-select indices for repos
	reports  []*scan.ScanReport

	// Global components
	keys    KeyMap
	help    help.Model
	spinner spinner.Model

	// View state
	loading   bool
	err       error
	statusMsg string
	showHelp  bool

	// Terminal size
	width  int
	height int

	// View-specific state (will be replaced with proper view models in later phases)
	repoListIndex int
	tabIndex      int    // for provider tabs: 0=All, 1=GitHub, 2=GitLab, 3=Bitbucket
	searchFilter  string // Substring search filter for repos
	searching     bool   // Whether we're in search mode
	addingRepoURL bool   // Whether we're in "add repo URL" mode
	repoURLInput  string // The URL being typed

	// Pagination
	repoPageSize   int    // Number of repos to load per page (default 50)
	hasMoreRepos   bool   // Whether there are more repos to load
	repoLoadCount  int    // Total repos requested so far
	loadedProvider string // The provider filter used to load current repos ("" for all)

	// Wizard state (used by wizard views - nolint to allow implementation)
	wizardStep     int    //nolint:unused // Current wizard step (0=select provider, 1=show instructions)
	wizardProvider string //nolint:unused // Selected provider type
}

// New creates a new TUI model
func New(cfg *config.Config) Model {
	// Auto-detect scan mode
	scanMode := "standalone"
	if srsURL := os.Getenv("SRS_ORCHESTRATOR_API_ENDPOINT"); srsURL != "" {
		scanMode = "remote"
	} else if cfg != nil && cfg.SRS.APIURL != "" {
		scanMode = "remote"
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColorPrimary)

	return Model{
		view:         ViewHome,
		config:       cfg,
		scanMode:     scanMode,
		selected:     make(map[int]bool),
		keys:         DefaultKeyMap(),
		help:         help.New(),
		spinner:      s,
		width:        80,
		height:       24,
		repoPageSize: 50, // Load 50 repos at a time
		hasMoreRepos: true,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tea.EnterAltScreen,
	)
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width

	case tea.KeyMsg:
		// Global key handling
		switch {
		case key.Matches(msg, m.keys.Quit):
			if m.view == ViewHome {
				return m, tea.Quit
			}
			// Go back to home from other views
			m.view = ViewHome
			return m, nil

		case key.Matches(msg, m.keys.Help):
			m.showHelp = !m.showHelp
			return m, nil

		case key.Matches(msg, m.keys.GoHome):
			m.view = ViewHome
			return m, nil

		case key.Matches(msg, m.keys.GoRepos):
			m.view = ViewRepos
			if len(m.repos) == 0 {
				m.loading = true
				return m, m.loadRepos()
			}
			return m, nil

		case key.Matches(msg, m.keys.GoResults):
			m.view = ViewResults
			return m, nil
		}

		// View-specific key handling
		switch m.view {
		case ViewHome:
			return m.updateHome(msg)
		case ViewRepos:
			return m.updateRepos(msg)
		case ViewScan:
			return m.updateScan(msg)
		case ViewResults:
			return m.updateResults(msg)
		case ViewWizard:
			return m.updateWizard(msg)
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case ChangeViewMsg:
		m.view = msg.View

	case ReposLoadingMsg:
		m.loading = true

	case ReposLoadedMsg:
		m.repos = msg.Repos
		m.loading = false
		m.statusMsg = ""
		m.repoLoadCount = msg.Limit
		m.loadedProvider = msg.Provider
		// If we got fewer repos than requested, there are no more to load
		m.hasMoreRepos = len(msg.Repos) >= msg.Limit

	case ScanStartMsg:
		m.loading = true
		m.statusMsg = "Starting scan..."
		return m, m.runScan(msg.Repos)

	case ScanCompleteMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
		} else {
			m.reports = append(m.reports, msg.Report)
			m.view = ViewResults
		}

	case ErrorMsg:
		m.err = msg.Err
		m.loading = false

	case StatusMsg:
		m.statusMsg = string(msg)
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model
func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	var content string

	// Render header
	header := m.renderHeader()

	// Render main content based on view
	switch m.view {
	case ViewHome:
		content = m.viewHome()
	case ViewRepos:
		content = m.viewRepos()
	case ViewScan:
		content = m.viewScan()
	case ViewResults:
		content = m.viewResults()
	case ViewWizard:
		content = m.viewWizard()
	}

	// Render footer
	footer := m.renderFooter()

	// Compose the full view
	return lipgloss.JoinVertical(lipgloss.Left, header, content, footer)
}

// renderHeader renders the app header
func (m Model) renderHeader() string {
	title := TitleStyle.Render(" SECURELENS ")

	// View tabs
	tabs := []string{"Home", "Repos", "Results"}
	var tabsRendered []string
	for i, tab := range tabs {
		style := InactiveTabStyle
		if (i == 0 && m.view == ViewHome) ||
			(i == 1 && m.view == ViewRepos) ||
			(i == 2 && m.view == ViewResults) {
			style = ActiveTabStyle
		}
		tabsRendered = append(tabsRendered, style.Render(tab))
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabsRendered...)

	// Mode indicator
	modeStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	mode := modeStyle.Render(" [" + m.scanMode + " mode]")

	headerLine := lipgloss.JoinHorizontal(lipgloss.Top, title, "  ", tabBar, mode)

	return headerLine + "\n" + lipgloss.NewStyle().
		Foreground(ColorBorder).
		Render(repeatChar("─", m.width)) + "\n"
}

// renderFooter renders the help/status footer
func (m Model) renderFooter() string {
	var footer string

	if m.err != nil {
		footer = ErrorStyle.Render("Error: " + m.err.Error())
	} else if m.statusMsg != "" {
		footer = SubtleStyle.Render(m.statusMsg)
	} else if m.showHelp {
		footer = m.help.View(m.keys)
	} else {
		footer = HelpStyle.Render("Press ? for help • q to quit")
	}

	return "\n" + lipgloss.NewStyle().
		Foreground(ColorBorder).
		Render(repeatChar("─", m.width)) + "\n" + footer
}

// Helper to repeat a character
func repeatChar(char string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += char
	}
	return result
}

// getProviderFilter returns the provider name for the current tab
func (m Model) getProviderFilter() string {
	switch m.tabIndex {
	case 1:
		return "github"
	case 2:
		return "gitlab"
	case 3:
		return "bitbucket"
	default:
		return "" // All providers
	}
}

// loadRepos returns a command to load repositories with pagination and provider filtering
func (m Model) loadRepos() tea.Cmd {
	limit := m.repoLoadCount + m.repoPageSize
	provider := m.getProviderFilter()
	return func() tea.Msg {
		ctx := context.Background()

		// Filter config by provider if a specific tab is selected
		cfg := m.config
		if provider != "" {
			cfg = scan.FilterConfigByProvider(m.config, provider)
		}

		repos, err := scan.DiscoverRepositories(ctx, cfg, limit, false)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ReposLoadedMsg{Repos: repos, Limit: limit, Provider: provider}
	}
}

// runScan executes scanning on selected repositories
func (m Model) runScan(repos []scan.DiscoveredRepository) tea.Cmd {
	return func() tea.Msg {
		if len(repos) == 0 {
			return ErrorMsg{Err: fmt.Errorf("no repositories selected")}
		}

		// For now, scan the first repository (bulk scan support in later phase)
		ctx := context.Background()
		report, err := scan.ScanRepository(ctx, m.config, repos[0], m.scanMode)
		if err != nil {
			return ScanCompleteMsg{Report: nil, Error: err}
		}
		return ScanCompleteMsg{Report: report, Error: nil}
	}
}
