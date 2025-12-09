package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	repos       []scan.DiscoveredRepository
	manualRepos []scan.DiscoveredRepository // Manually added repos (persist across reloads)
	selected    map[int]bool                // multi-select indices for repos
	reports     []*scan.ScanReport

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
	orgIndex      int    // Current organization index within provider (for GitHub/GitLab groups)

	// Pagination
	repoPageSize   int    // Number of repos to load per page (default 50)
	hasMoreRepos   bool   // Whether there are more repos to load
	repoLoadCount  int    // Total repos requested so far
	loadedProvider string // The provider filter used to load current repos ("" for all)

	// Wizard state (used by wizard views - nolint to allow implementation)
	wizardStep     int    //nolint:unused // Current wizard step (0=select provider, 1=show instructions)
	wizardProvider string //nolint:unused // Selected provider type

	// Report browser state
	reportsDir         string              // Base reports directory (default "reports")
	reportBrowserPath  []string            // Current navigation path ["owner", "repo", "branch", "commit"]
	reportBrowserItems []ReportBrowserItem // Current items at this level
	reportListIndex    int                 // Selected item in the list
	currentReport      *scan.ScanReport    // Currently viewed report
	currentReportPath  string              // Path to currently viewed report
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
		reportsDir:   "reports", // Default reports directory
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
		// IMPORTANT: Handle input modes FIRST before global keys
		// This prevents 'q' from quitting when typing in search/URL input
		if m.searching || m.addingRepoURL {
			return m.updateRepos(msg)
		}

		// Global key handling (only when not in input mode)
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
			// Reset browser state and load root level
			m.reportBrowserPath = nil
			m.currentReport = nil
			m.loading = true
			return m, m.loadReportBrowserItems()
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
		// Merge manual repos with discovered repos (manual repos first)
		m.repos = append(m.manualRepos, msg.Repos...)
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
			m.currentReport = msg.Report
			m.view = ViewResults
			// Auto-save the report
			savedPath, err := saveReport(m.reportsDir, msg.Report)
			if err != nil {
				m.statusMsg = "Report completed (save failed: " + err.Error() + ")"
			} else {
				m.statusMsg = "Report saved to " + savedPath
				m.currentReportPath = savedPath
			}
		}

	case ErrorMsg:
		m.err = msg.Err
		m.loading = false

	case StatusMsg:
		m.statusMsg = string(msg)

	case ReportBrowserLoadedMsg:
		m.loading = false
		m.reportBrowserItems = msg.Items
		m.reportListIndex = 0

	case ReportDetailLoadedMsg:
		m.loading = false
		m.currentReport = msg.Report
		m.currentReportPath = msg.Path
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

// getOrganizations returns the list of organizations for the current provider tab
func (m Model) getOrganizations() []string {
	if m.config == nil {
		return nil
	}

	switch m.tabIndex {
	case 1: // GitHub
		var orgs []string
		for _, gh := range m.config.Git.GitHub {
			orgs = append(orgs, gh.Organizations...)
		}
		return orgs
	case 2: // GitLab - use instance names as "organizations"
		var orgs []string
		for _, gl := range m.config.Git.GitLab {
			orgs = append(orgs, gl.Name)
		}
		return orgs
	case 3: // Bitbucket - use workspace names
		var orgs []string
		for _, bb := range m.config.Git.Bitbucket {
			orgs = append(orgs, bb.Workspace)
		}
		return orgs
	default:
		return nil
	}
}

// getCurrentOrg returns the currently selected organization name, or "All" if none selected
func (m Model) getCurrentOrg() string {
	orgs := m.getOrganizations()
	if len(orgs) == 0 || m.orgIndex == 0 {
		return "All"
	}
	// orgIndex 0 = All, 1 = first org, etc.
	if m.orgIndex > 0 && m.orgIndex <= len(orgs) {
		return orgs[m.orgIndex-1]
	}
	return "All"
}

// loadRepos returns a command to load repositories with pagination and provider filtering
func (m Model) loadRepos() tea.Cmd {
	limit := m.repoLoadCount + m.repoPageSize
	provider := m.getProviderFilter()
	orgIndex := m.orgIndex
	orgs := m.getOrganizations()
	cfg := m.config
	return func() tea.Msg {
		ctx := context.Background()

		// Filter config by provider if a specific tab is selected
		filteredCfg := cfg
		if provider != "" {
			filteredCfg = scan.FilterConfigByProvider(cfg, provider)
		}

		// Further filter by organization if one is selected
		if orgIndex > 0 && len(orgs) > 0 && orgIndex <= len(orgs) {
			selectedOrg := orgs[orgIndex-1]
			filteredCfg = filterConfigByOrg(filteredCfg, provider, selectedOrg)
		}

		repos, err := scan.DiscoverRepositories(ctx, filteredCfg, limit, false)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ReposLoadedMsg{Repos: repos, Limit: limit, Provider: provider}
	}
}

// filterConfigByOrg creates a filtered config with only the specified organization
func filterConfigByOrg(cfg *config.Config, provider, org string) *config.Config {
	if cfg == nil {
		return cfg
	}

	filtered := &config.Config{
		Database:  cfg.Database,
		SRS:       cfg.SRS,
		Scanners:  cfg.Scanners,
		Scanning:  cfg.Scanning,
		Output:    cfg.Output,
		Discovery: cfg.Discovery,
	}

	switch provider {
	case "github":
		// Filter GitHub configs to only include the selected organization
		for _, gh := range cfg.Git.GitHub {
			filteredOrgs := []string{}
			for _, o := range gh.Organizations {
				if o == org {
					filteredOrgs = append(filteredOrgs, o)
				}
			}
			if len(filteredOrgs) > 0 {
				newGH := gh
				newGH.Organizations = filteredOrgs
				filtered.Git.GitHub = append(filtered.Git.GitHub, newGH)
			}
		}
	case "gitlab":
		// Filter GitLab configs by instance name
		for _, gl := range cfg.Git.GitLab {
			if gl.Name == org {
				filtered.Git.GitLab = append(filtered.Git.GitLab, gl)
			}
		}
	case "bitbucket":
		// Filter Bitbucket configs by workspace
		for _, bb := range cfg.Git.Bitbucket {
			if bb.Workspace == org {
				filtered.Git.Bitbucket = append(filtered.Git.Bitbucket, bb)
			}
		}
	default:
		return cfg
	}

	return filtered
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

// loadReportBrowserItems loads items at the current browser path
func (m Model) loadReportBrowserItems() tea.Cmd {
	reportsDir := m.reportsDir
	browserPath := m.reportBrowserPath
	return func() tea.Msg {
		items, err := scanReportDirectory(reportsDir, browserPath)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		level := ReportBrowserLevel(len(browserPath))
		return ReportBrowserLoadedMsg{
			Level: level,
			Items: items,
			Path:  buildBrowserPath(reportsDir, browserPath),
		}
	}
}

// loadReportDetail loads a specific report for viewing
func (m Model) loadReportDetail(reportPath string) tea.Cmd {
	return func() tea.Msg {
		report, err := loadReportFromFile(reportPath)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ReportDetailLoadedMsg{Report: report, Path: reportPath}
	}
}

// getCurrentBrowserLevel returns the current navigation level
func (m Model) getCurrentBrowserLevel() ReportBrowserLevel {
	return ReportBrowserLevel(len(m.reportBrowserPath))
}

// getBreadcrumb returns a breadcrumb string for the current path
func (m Model) getBreadcrumb() string {
	if len(m.reportBrowserPath) == 0 {
		return "reports/"
	}
	return "reports/" + strings.Join(m.reportBrowserPath, "/") + "/"
}

// scanReportDirectory scans a directory level and returns items
func scanReportDirectory(baseDir string, browserPath []string) ([]ReportBrowserItem, error) {
	fullPath := filepath.Join(baseDir)
	for _, p := range browserPath {
		fullPath = filepath.Join(fullPath, p)
	}

	// Check if directory exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return []ReportBrowserItem{}, nil
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var items []ReportBrowserItem
	for _, entry := range entries {
		// Skip hidden files
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		item := ReportBrowserItem{
			Name:  entry.Name(),
			Path:  filepath.Join(fullPath, entry.Name()),
			IsDir: entry.IsDir(),
		}

		if entry.IsDir() {
			// Count children
			children, _ := os.ReadDir(item.Path)
			item.Children = len(children)
		} else {
			// Only include .json files (reports)
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
		}

		items = append(items, item)
	}

	// Sort directories first, then alphabetically
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir // Directories first
		}
		return items[i].Name < items[j].Name
	})

	return items, nil
}

// buildBrowserPath builds the full path string from base and path parts
func buildBrowserPath(baseDir string, browserPath []string) string {
	fullPath := baseDir
	for _, p := range browserPath {
		fullPath = filepath.Join(fullPath, p)
	}
	return fullPath
}

// loadReportFromFile loads and parses a report JSON file
func loadReportFromFile(reportPath string) (*scan.ScanReport, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}

	var report scan.ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	return &report, nil
}

// saveReport saves a scan report to the reports directory structure:
// reports/{owner}/{repo}/{branch}/{commit}/report-{timestamp}.json
func saveReport(baseDir string, report *scan.ScanReport) (string, error) {
	// Build the report path
	reportDir := buildReportPath(baseDir, report)

	// Create directory structure
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}

	// Generate filename with timestamp
	timestamp := strings.ReplaceAll(report.Timestamp, ":", "-")
	timestamp = strings.ReplaceAll(timestamp, "T", "_")
	if idx := strings.Index(timestamp, "Z"); idx > 0 {
		timestamp = timestamp[:idx]
	}
	filename := fmt.Sprintf("report-%s.json", timestamp)
	reportPath := filepath.Join(reportDir, filename)

	// Marshal report to JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}

	// Write the report file
	if err := os.WriteFile(reportPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	// Also write/update latest.json for easy access
	latestPath := filepath.Join(reportDir, "latest.json")
	_ = os.Remove(latestPath) // Remove existing
	if err := os.WriteFile(latestPath, data, 0644); err != nil {
		// Non-fatal, just log
		return reportPath, nil
	}

	return reportPath, nil
}

// buildReportPath creates the commit-based report directory structure:
// reports/{owner}/{repo}/{branch}/{commit}/
func buildReportPath(baseDir string, report *scan.ScanReport) string {
	// Parse the repository URL to extract owner/repo
	repoURL := report.Repository
	owner := "unknown"
	repo := "unknown"

	// Try to extract from URL
	// Handle: https://github.com/owner/repo, https://gitlab.com/owner/repo, etc.
	repoURL = strings.TrimSuffix(repoURL, ".git")
	parts := strings.Split(repoURL, "/")
	if len(parts) >= 2 {
		repo = parts[len(parts)-1]
		owner = parts[len(parts)-2]
	}

	branch := report.Branch
	if branch == "" {
		branch = "default"
	}
	// Sanitize branch name (replace / with -)
	branch = strings.ReplaceAll(branch, "/", "-")

	commit := report.Commit
	if commit == "" {
		commit = "unknown"
	}
	// Use short commit hash
	if len(commit) > 8 {
		commit = commit[:8]
	}

	return filepath.Join(baseDir, owner, repo, branch, commit)
}
