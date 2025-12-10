package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	"github.com/splunk/securelens/pkg/database"
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

	// Database
	db             database.DB // SQLite database for offline repository browsing
	useDatabase    bool        // Whether to load repos from database (offline mode)

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

	// Branch selection state
	branchSelectRepo     scan.DiscoveredRepository   // Repo being configured for scan
	branchSelectBranches []string                    // Available branches
	branchSelectIndex    int                         // Currently highlighted branch
	branchSelected       map[int]bool                // Selected branches (multi-select)
	repoQueue            []scan.DiscoveredRepository // Queue of repos waiting for branch selection
	branchSearch         string                      // Branch search/filter string
	branchSearching      bool                        // Whether we're in branch search mode

	// Scan progress state
	scanItems      []ScanItem // All scan items with their status
	currentScanIdx int        // Index of currently running scan (-1 if none)
	scanListIndex  int        // Selected item in scan progress view
	scanLogs       []string   // Recent scanner log messages (circular buffer, max 10)
	scanLogChan    chan string // Channel for streaming log messages from scans

	// VulnsDb state
	vulnType         VulnType          // Current vulnerability type tab (SCA, SAST, Secrets)
	vulnListIndex    int               // Selected item in vulnerability list
	vulnSelected     map[int]bool      // Multi-select for bulk actions
	vulnSearch       string            // Search filter
	vulnSearching    bool              // Whether we're in search mode
	vulnStatusFilter string            // Filter by status (open, fixed, ignored, "")
	vulnSortField    VulnSortField     // Current sort field
	vulnSortAsc      bool              // Sort direction
	scaVulns         []SCAVulnItem     // SCA findings from database
	sastVulns        []SASTVulnItem    // SAST findings from database
	secretsVulns     []SecretsVulnItem // Secrets findings from database
	vulnShowActions  bool              // Show bulk action menu
	vulnRowExpanded  bool              // Whether current row is expanded (show full content)

	// License view state
	licenseVulns        []LicenseVulnItem // License findings from database
	licenseListIndex    int               // Selected item in license list
	licenseSelected     map[int]bool      // Multi-select for bulk actions
	licenseSearch       string            // Search filter
	licenseSearching    bool              // Whether we're in search mode
	licenseStatusFilter string            // Filter by status
	licenseShowActions  bool              // Show bulk action menu
	licenseRowExpanded  bool              // Whether current row is expanded
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

	// Initialize SQLite database for offline repository browsing
	var db database.DB
	useDatabase := false
	if sqliteDB, err := database.New(database.Config{Driver: "sqlite"}); err == nil {
		db = sqliteDB
		useDatabase = true // Default to using database if available
	}

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
		repoPageSize: 50,  // Load 50 repos at a time
		hasMoreRepos: true,
		reportsDir:   "reports", // Default reports directory
		db:           db,
		useDatabase:  useDatabase,
		scanLogChan:  make(chan string, 100), // Buffered channel for scan logs
		// VulnsDb defaults
		vulnType:     VulnTypeSCA,
		vulnSelected: make(map[int]bool),
		vulnSortAsc:  false, // Descending by default (newest/highest first)
		// License defaults
		licenseSelected: make(map[int]bool),
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tea.EnterAltScreen,
		m.listenForScanLogs(),
	)
}

// listenForScanLogs returns a command that listens for log messages on the channel
func (m Model) listenForScanLogs() tea.Cmd {
	return func() tea.Msg {
		msg := <-m.scanLogChan
		return ScanLogMsg{Message: msg}
	}
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
		if m.branchSearching {
			return m.updateBranchSelect(msg)
		}
		if m.vulnSearching {
			return m.updateVulnsDb(msg)
		}
		if m.licenseSearching {
			return m.updateLicenses(msg)
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

		case key.Matches(msg, m.keys.GoVulnsDb):
			m.view = ViewVulnsDb
			m.loading = true
			return m, m.loadVulns()

		case key.Matches(msg, m.keys.GoLicenses):
			m.view = ViewLicenses
			m.loading = true
			return m, m.loadLicenses()
		}

		// View-specific key handling
		switch m.view {
		case ViewHome:
			return m.updateHome(msg)
		case ViewRepos:
			return m.updateRepos(msg)
		case ViewBranchSelect:
			return m.updateBranchSelect(msg)
		case ViewScan:
			return m.updateScan(msg)
		case ViewResults:
			return m.updateResults(msg)
		case ViewVulnsDb:
			return m.updateVulnsDb(msg)
		case ViewLicenses:
			return m.updateLicenses(msg)
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
		m.repoLoadCount = msg.Limit
		m.loadedProvider = msg.Provider
		// If we got fewer repos than requested, there are no more to load
		m.hasMoreRepos = len(msg.Repos) >= msg.Limit
		// Show data source in status
		if msg.FromDatabase {
			m.statusMsg = fmt.Sprintf("Loaded %d repos from database (press 'r' to refresh from API)", len(msg.Repos))
		} else {
			m.statusMsg = fmt.Sprintf("Loaded %d repos from API", len(msg.Repos))
		}

	case ScanStartMsg:
		m.loading = true
		m.statusMsg = "Starting scan..."
		return m, m.runScan(msg.Repos)

	case ScanCompleteMsg:
		m.loading = false

		// Update the current scan item's status
		if m.currentScanIdx >= 0 && m.currentScanIdx < len(m.scanItems) {
			if msg.Error != nil {
				m.scanItems[m.currentScanIdx].Status = ScanStatusError
				m.scanItems[m.currentScanIdx].Error = msg.Error.Error()
			} else {
				m.scanItems[m.currentScanIdx].Status = ScanStatusComplete
				m.reports = append(m.reports, msg.Report)
				// Auto-save the report
				savedPath, err := saveReport(m.reportsDir, msg.Report)
				if err != nil {
					m.scanItems[m.currentScanIdx].ReportPath = "(save failed)"
				} else {
					m.scanItems[m.currentScanIdx].ReportPath = savedPath
				}

				// Save findings to database
				if m.db != nil && msg.Report != nil {
					item := m.scanItems[m.currentScanIdx]
					saveFindingsToDatabase(m.db, msg.Report, item.Repo.Provider, item.Repo.FullName, item.Branch)
				}
			}
		}

		// Find next pending scan
		nextIdx := -1
		for i := m.currentScanIdx + 1; i < len(m.scanItems); i++ {
			if m.scanItems[i].Status == ScanStatusPending {
				nextIdx = i
				break
			}
		}

		if nextIdx >= 0 {
			// Start the next scan
			m.currentScanIdx = nextIdx
			m.scanItems[nextIdx].Status = ScanStatusRunning
			m.loading = true
			item := m.scanItems[nextIdx]
			m.statusMsg = fmt.Sprintf("Scanning %s @ %s...", item.Repo.FullName, item.Branch)
			return m, m.runScanWithBranch(item.Repo, item.Branch)
		}

		// All scans complete - show summary
		m.currentScanIdx = -1
		completedCount := 0
		errorCount := 0
		for _, item := range m.scanItems {
			switch item.Status {
			case ScanStatusComplete:
				completedCount++
			case ScanStatusError:
				errorCount++
			}
		}
		m.statusMsg = fmt.Sprintf("All scans complete: %d succeeded, %d failed", completedCount, errorCount)

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

	case BranchesLoadedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
			m.view = ViewRepos
		} else {
			m.branchSelectRepo = msg.Repo
			m.branchSelectBranches = msg.Branches
			m.branchSelectIndex = 0
			m.branchSelected = make(map[int]bool)
			m.branchSearch = ""         // Reset search when loading new repo
			m.branchSearching = false
			// Pre-select "main" or "master" if available
			for i, branch := range msg.Branches {
				if branch == "main" || branch == "master" {
					m.branchSelected[i] = true
					m.branchSelectIndex = i
					break
				}
			}
			m.view = ViewBranchSelect
		}

	case SearchResultsMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
		} else {
			// Prepend search results to repos list (after manual repos)
			m.repos = append(m.manualRepos, msg.Repos...)
			m.statusMsg = fmt.Sprintf("Found %d repos for \"%s\"", len(msg.Repos), msg.Query)
			m.repoListIndex = 0
		}

	case VulnsLoadedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
		} else {
			m.scaVulns = msg.SCAItems
			m.sastVulns = msg.SASTItems
			m.secretsVulns = msg.SecretItems
			m.vulnListIndex = 0
			m.statusMsg = fmt.Sprintf("Loaded %d vulnerabilities", msg.Total)
		}

	case LicensesLoadedMsg:
		m.loading = false
		if msg.Error != nil {
			m.err = msg.Error
		} else {
			m.licenseVulns = msg.Items
			m.licenseListIndex = 0
			m.statusMsg = fmt.Sprintf("Loaded %d license findings", msg.Total)
		}

	case ScanLogMsg:
		// Add to circular buffer of scan logs (keep last 8)
		m.scanLogs = append(m.scanLogs, msg.Message)
		if len(m.scanLogs) > 8 {
			m.scanLogs = m.scanLogs[1:]
		}
		// Continue listening for more log messages
		cmds = append(cmds, m.listenForScanLogs())
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
	case ViewBranchSelect:
		content = m.viewBranchSelect()
	case ViewScan:
		content = m.viewScan()
	case ViewResults:
		content = m.viewResults()
	case ViewVulnsDb:
		content = m.viewVulnsDb()
	case ViewLicenses:
		content = m.viewLicenses()
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
	tabs := []string{"Home", "Repos", "Results", "VulnsDb", "Licenses"}
	var tabsRendered []string
	for i, tab := range tabs {
		style := InactiveTabStyle
		if (i == 0 && m.view == ViewHome) ||
			(i == 1 && m.view == ViewRepos) ||
			(i == 2 && m.view == ViewResults) ||
			(i == 3 && m.view == ViewVulnsDb) ||
			(i == 4 && m.view == ViewLicenses) {
			style = ActiveTabStyle
		}
		tabsRendered = append(tabsRendered, style.Render(tab))
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, " ")
	for i, tab := range tabsRendered {
		if i > 0 {
			tabBar = lipgloss.JoinHorizontal(lipgloss.Top, tabBar, "  ", tab)
		} else {
			tabBar = lipgloss.JoinHorizontal(lipgloss.Top, tabBar, tab)
		}
	}

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
	db := m.db
	useDatabase := m.useDatabase

	// Get selected org name for database filtering
	selectedOrg := ""
	if orgIndex > 0 && len(orgs) > 0 && orgIndex <= len(orgs) {
		selectedOrg = orgs[orgIndex-1]
	}

	return func() tea.Msg {
		ctx := context.Background()

		// If database is available and enabled, load from SQLite first
		if useDatabase && db != nil {
			repos, err := loadReposFromDatabase(ctx, db, provider, selectedOrg, limit)
			if err == nil && len(repos) > 0 {
				return ReposLoadedMsg{Repos: repos, Limit: limit, Provider: provider, FromDatabase: true}
			}
			// If database is empty or error, fall through to API
		}

		// Fall back to API
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
		return ReposLoadedMsg{Repos: repos, Limit: limit, Provider: provider, FromDatabase: false}
	}
}

// loadReposFromDatabase loads repositories from SQLite database
func loadReposFromDatabase(ctx context.Context, db database.DB, provider, org string, limit int) ([]scan.DiscoveredRepository, error) {
	opts := database.ListRepositoriesOptions{
		Provider: provider,
		Limit:    limit,
	}
	// Filter by organization using Search field (matches full_name prefix like "smartlook/")
	if org != "" {
		opts.Search = org + "/"
	}

	dbRepos, err := db.ListRepositories(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Convert database.Repository to scan.DiscoveredRepository
	repos := make([]scan.DiscoveredRepository, 0, len(dbRepos))
	for _, r := range dbRepos {
		repos = append(repos, scan.DiscoveredRepository{
			Provider:    r.Provider,
			Name:        r.Name,
			FullName:    r.FullName,
			URL:         r.URL,
			IsPrivate:   r.IsPrivate,
			Language:    r.Language,
			Description: r.Description,
		})
	}

	return repos, nil
}

// refreshReposFromAPI forces a refresh from the API and updates the database
func (m Model) refreshReposFromAPI() tea.Cmd {
	limit := m.repoLoadCount + m.repoPageSize
	provider := m.getProviderFilter()
	orgIndex := m.orgIndex
	orgs := m.getOrganizations()
	cfg := m.config
	db := m.db

	return func() tea.Msg {
		ctx := context.Background()

		// Load from API
		filteredCfg := cfg
		if provider != "" {
			filteredCfg = scan.FilterConfigByProvider(cfg, provider)
		}

		if orgIndex > 0 && len(orgs) > 0 && orgIndex <= len(orgs) {
			selectedOrg := orgs[orgIndex-1]
			filteredCfg = filterConfigByOrg(filteredCfg, provider, selectedOrg)
		}

		repos, err := scan.DiscoverRepositories(ctx, filteredCfg, limit, false)
		if err != nil {
			return ErrorMsg{Err: err}
		}

		// Save to database if available
		if db != nil {
			for _, repo := range repos {
				dbRepo := &database.Repository{
					Provider:    repo.Provider,
					Name:        repo.Name,
					FullName:    repo.FullName,
					URL:         repo.URL,
					CloneURL:    repo.URL,
					IsPrivate:   repo.IsPrivate,
					Language:    repo.Language,
					Description: repo.Description,
					Source:      "api-refresh",
				}
				_ = db.UpsertRepository(ctx, dbRepo)
			}
		}

		return ReposLoadedMsg{Repos: repos, Limit: limit, Provider: provider, FromDatabase: false}
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

// searchRepos searches for repositories via API
func (m Model) searchRepos(query string) tea.Cmd {
	cfg := m.config
	provider := m.getProviderFilter()
	limit := m.repoPageSize
	return func() tea.Msg {
		ctx := context.Background()
		repos, err := scan.SearchRepositories(ctx, cfg, query, provider, limit)
		if err != nil {
			return SearchResultsMsg{Query: query, Repos: nil, Error: err}
		}
		return SearchResultsMsg{Query: query, Repos: repos, Error: nil}
	}
}

// loadBranches fetches branches for a repository
func (m Model) loadBranches(repo scan.DiscoveredRepository) tea.Cmd {
	cfg := m.config
	return func() tea.Msg {
		ctx := context.Background()
		branches, err := scan.FetchBranches(ctx, cfg, repo)
		if err != nil {
			return BranchesLoadedMsg{Repo: repo, Branches: nil, Error: err}
		}
		// If no branches found, default to main
		if len(branches) == 0 {
			branches = []string{"main"}
		}
		return BranchesLoadedMsg{Repo: repo, Branches: branches, Error: nil}
	}
}

// loadVulns loads vulnerabilities from the database
func (m Model) loadVulns() tea.Cmd {
	db := m.db
	return func() tea.Msg {
		if db == nil {
			return VulnsLoadedMsg{Error: fmt.Errorf("database not available")}
		}

		ctx := context.Background()
		var scaItems []SCAVulnItem
		var sastItems []SASTVulnItem
		var secretItems []SecretsVulnItem
		total := 0

		// Load SCA findings
		scaFindings, err := db.ListSCAFindings(ctx, database.ListSCAFindingsOptions{Limit: 1000})
		if err == nil {
			for _, f := range scaFindings {
				scaItems = append(scaItems, SCAVulnItem{
					ID:              f.ID,
					PrimaryKey:      f.PrimaryUniqueKey,
					Provider:        f.Provider,
					Repository:      f.Repository,
					Branch:          f.Branch,
					Commit:          f.Commit,
					Package:         f.Package,
					Version:         f.InstalledVersion,
					VulnerabilityID: f.VulnerabilityID,
					Severity:        f.Severity,
					Title:           f.Title,
					Status:          f.Status,
					JiraTicket:      f.JiraTicket,
					FirstSeen:       f.FirstSeenAt.Format("2006-01-02"),
					LastSeen:        f.LastSeenAt.Format("2006-01-02"),
				})
			}
			total += len(scaFindings)
		}

		// Load SAST findings
		sastFindings, err := db.ListSASTFindings(ctx, database.ListSASTFindingsOptions{Limit: 1000})
		if err == nil {
			for _, f := range sastFindings {
				sastItems = append(sastItems, SASTVulnItem{
					ID:         f.ID,
					PrimaryKey: f.PrimaryUniqueKey,
					Provider:   f.Provider,
					Repository: f.Repository,
					Branch:     f.Branch,
					Commit:     f.Commit,
					Scanner:    f.Scanner,
					CheckID:    f.CheckID,
					Severity:   f.Severity,
					Message:    f.Message,
					FilePath:   f.FilePath,
					Line:       f.LineStart,
					Status:     f.Status,
					JiraTicket: f.JiraTicket,
					FirstSeen:  f.FirstSeenAt.Format("2006-01-02"),
					LastSeen:   f.LastSeenAt.Format("2006-01-02"),
				})
			}
			total += len(sastFindings)
		}

		// Load Secrets findings
		secretsFindings, err := db.ListSecretsFindings(ctx, database.ListSecretsFindingsOptions{Limit: 1000})
		if err == nil {
			for _, f := range secretsFindings {
				secretItems = append(secretItems, SecretsVulnItem{
					ID:           f.ID,
					PrimaryKey:   f.PrimaryUniqueKey,
					Provider:     f.Provider,
					Repository:   f.Repository,
					Branch:       f.Branch,
					Commit:       f.Commit,
					DetectorName: f.DetectorName,
					Verified:     f.Verified,
					FilePath:     f.FilePath,
					Line:         f.LineNumber,
					Severity:     f.Severity,
					Status:       f.Status,
					JiraTicket:   f.JiraTicket,
					FirstSeen:    f.FirstSeenAt.Format("2006-01-02"),
					LastSeen:     f.LastSeenAt.Format("2006-01-02"),
				})
			}
			total += len(secretsFindings)
		}

		return VulnsLoadedMsg{
			SCAItems:    scaItems,
			SASTItems:   sastItems,
			SecretItems: secretItems,
			Total:       total,
		}
	}
}

// loadLicenses loads license findings from the database
func (m Model) loadLicenses() tea.Cmd {
	db := m.db
	return func() tea.Msg {
		if db == nil {
			return LicensesLoadedMsg{Error: fmt.Errorf("database not available")}
		}

		ctx := context.Background()
		var items []LicenseVulnItem

		// Load License findings
		licenseFindings, err := db.ListLicenseFindings(ctx, database.ListLicenseFindingsOptions{Limit: 1000})
		if err != nil {
			return LicensesLoadedMsg{Error: err}
		}

		for _, f := range licenseFindings {
			items = append(items, LicenseVulnItem{
				ID:             f.ID,
				PrimaryKey:     f.PrimaryUniqueKey,
				Provider:       f.Provider,
				Repository:     f.Repository,
				Branch:         f.Branch,
				Commit:         f.Commit,
				Package:        f.Package,
				Version:        f.Version,
				License:        f.License,
				Classification: f.Classification,
				PkgPath:        f.PkgPath,
				PkgType:        f.PkgType,
				Severity:       f.Severity,
				Status:         f.Status,
				JiraTicket:     f.JiraTicket,
				FirstSeen:      f.FirstSeenAt.Format("2006-01-02"),
				LastSeen:       f.LastSeenAt.Format("2006-01-02"),
			})
		}

		return LicensesLoadedMsg{
			Items: items,
			Total: len(items),
		}
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

// runScanWithBranch executes scanning on a repository with specific branch
func (m Model) runScanWithBranch(repo scan.DiscoveredRepository, branch string) tea.Cmd {
	cfg := m.config
	scanMode := m.scanMode
	logChan := m.scanLogChan
	return func() tea.Msg {
		ctx := context.Background()

		// Send progress updates to the log channel
		sendLog := func(msg string) {
			select {
			case logChan <- msg:
			default:
				// Channel full, skip
			}
		}

		sendLog(fmt.Sprintf("Starting scan: %s @ %s", repo.FullName, branch))

		// Run scan with progress logging
		report, err := scan.ScanRepositoryWithBranchAndProgress(ctx, cfg, repo, branch, scanMode, sendLog)
		if err != nil {
			sendLog(fmt.Sprintf("Scan failed: %s", err.Error()))
			return ScanCompleteMsg{Report: nil, Error: err}
		}

		sendLog(fmt.Sprintf("Scan complete: %s", repo.FullName))
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
// It handles both combined reports (latest.json) and raw scanner outputs
func loadReportFromFile(reportPath string) (*scan.ScanReport, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}

	// First try to parse as a ScanReport
	var report scan.ScanReport
	if err := json.Unmarshal(data, &report); err == nil {
		// Check if it's a valid ScanReport (has key fields)
		if report.Repository != "" || report.Status != "" || len(report.Scanners) > 0 {
			return &report, nil
		}
	}

	// If not a ScanReport, it might be a raw scanner output
	// Create a synthetic report from the raw output
	filename := filepath.Base(reportPath)
	scannerName := detectScannerFromFilename(filename)

	// Parse raw output based on scanner type
	rawReport := &scan.ScanReport{
		Repository: "(raw scanner output)",
		Status:     "COMPLETE",
		Timestamp:  "",
		Scanners:   []string{scannerName},
		Results:    make(map[string]interface{}),
	}

	switch scannerName {
	case "trufflehog":
		// Trufflehog outputs NDJSON (newline-delimited JSON)
		var findings []map[string]interface{}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var finding map[string]interface{}
			if err := json.Unmarshal([]byte(line), &finding); err == nil {
				if _, ok := finding["DetectorName"]; ok {
					findings = append(findings, finding)
				}
			}
		}
		rawReport.Results[scannerName] = map[string]interface{}{
			"status":         "COMPLETE",
			"findings_count": len(findings),
			"findings":       findings,
		}

	case "opengrep":
		// OpenGrep outputs a JSON object with "results" array
		var ogResults map[string]interface{}
		if err := json.Unmarshal(data, &ogResults); err == nil {
			findingsCount := 0
			if results, ok := ogResults["results"].([]interface{}); ok {
				findingsCount = len(results)
			}
			rawReport.Results[scannerName] = map[string]interface{}{
				"status":         "COMPLETE",
				"findings_count": findingsCount,
				"findings":       ogResults["results"],
				"by_severity":    countSeveritiesFromOpengrep(ogResults),
			}
		}

	case "trivy":
		// Trivy outputs a JSON object with "Results" array containing vulnerabilities
		var trivyResults map[string]interface{}
		if err := json.Unmarshal(data, &trivyResults); err == nil {
			vulnCount := 0
			if results, ok := trivyResults["Results"].([]interface{}); ok {
				for _, r := range results {
					if result, ok := r.(map[string]interface{}); ok {
						if vulns, ok := result["Vulnerabilities"].([]interface{}); ok {
							vulnCount += len(vulns)
						}
					}
				}
			}
			rawReport.Results[scannerName] = map[string]interface{}{
				"status":                "COMPLETE",
				"vulnerabilities_count": vulnCount,
				"results":               trivyResults["Results"],
			}
		}

	default:
		// Unknown format - try to parse as generic JSON
		var generic interface{}
		if err := json.Unmarshal(data, &generic); err == nil {
			rawReport.Results[scannerName] = map[string]interface{}{
				"status": "COMPLETE",
				"raw":    generic,
			}
		}
	}

	return rawReport, nil
}

// detectScannerFromFilename extracts scanner name from filename
func detectScannerFromFilename(filename string) string {
	filename = strings.ToLower(filename)
	if strings.Contains(filename, "trufflehog") {
		return "trufflehog"
	}
	if strings.Contains(filename, "opengrep") || strings.Contains(filename, "semgrep") {
		return "opengrep"
	}
	if strings.Contains(filename, "trivy") {
		return "trivy"
	}
	// Default: use filename without extension
	return strings.TrimSuffix(filename, ".json")
}

// countSeveritiesFromOpengrep counts findings by severity for opengrep results
func countSeveritiesFromOpengrep(results map[string]interface{}) map[string]int {
	counts := make(map[string]int)
	if findings, ok := results["results"].([]interface{}); ok {
		for _, f := range findings {
			if finding, ok := f.(map[string]interface{}); ok {
				if extra, ok := finding["extra"].(map[string]interface{}); ok {
					if sev, ok := extra["severity"].(string); ok {
						counts[sev]++
					}
				}
			}
		}
	}
	return counts
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

// ============================================================================
// Database Integration - Save findings to SQLite after scan completion
// ============================================================================

// saveFindingsToDatabase saves all findings from a scan report to the database
// This handles SCA (Trivy), SAST (OpenGrep/Semgrep), and Secrets (TruffleHog) findings
func saveFindingsToDatabase(db database.DB, report *scan.ScanReport, provider, repoFullName, branch string) {
	if db == nil || report == nil {
		slog.Warn("saveFindingsToDatabase: db or report is nil", "db_nil", db == nil, "report_nil", report == nil)
		return
	}

	ctx := context.Background()
	commit := report.Commit
	if commit == "" {
		commit = "unknown"
	}

	slog.Info("saveFindingsToDatabase: processing report",
		"provider", provider,
		"repo", repoFullName,
		"branch", branch,
		"commit", commit,
		"scanners", report.Scanners,
		"results_count", len(report.Results))

	// Track found findings for fix detection
	var scaKeys []string
	var sastKeys []string
	var secretsKeys []string

	// Process each scanner's results
	for scanner, rawResult := range report.Results {
		result, ok := rawResult.(map[string]interface{})
		if !ok {
			slog.Warn("saveFindingsToDatabase: failed to cast result", "scanner", scanner)
			continue
		}

		slog.Info("saveFindingsToDatabase: processing scanner", "scanner", scanner, "result_keys", getMapKeys(result))

		switch scanner {
		case "trivy":
			scaKeys = saveTrivyFindings(ctx, db, result, provider, repoFullName, branch, commit)
			slog.Info("saveFindingsToDatabase: trivy findings saved", "count", len(scaKeys))
		case "opengrep", "semgrep":
			sastKeys = saveSASTFindings(ctx, db, result, scanner, provider, repoFullName, branch, commit)
			slog.Info("saveFindingsToDatabase: sast findings saved", "count", len(sastKeys))
		case "trufflehog":
			secretsKeys = saveSecretsFindings(ctx, db, result, provider, repoFullName, branch, commit)
			slog.Info("saveFindingsToDatabase: secrets findings saved", "count", len(secretsKeys))
		}
	}

	// Mark missing findings as fixed (comparing with previous scan)
	if len(scaKeys) > 0 {
		_ = db.MarkSCAFindingsFixed(ctx, provider, repoFullName, branch, commit, scaKeys)
	}
	if len(sastKeys) > 0 {
		_ = db.MarkSASTFindingsFixed(ctx, provider, repoFullName, branch, commit, sastKeys)
	}
	if len(secretsKeys) > 0 {
		_ = db.MarkSecretsFindingsFixed(ctx, provider, repoFullName, branch, commit, secretsKeys)
	}
}

// saveTrivyFindings saves Trivy SCA findings to the database
func saveTrivyFindings(ctx context.Context, db database.DB, result map[string]interface{}, provider, repo, branch, commit string) []string {
	var foundKeys []string

	slog.Info("saveTrivyFindings: starting", "result_keys", getMapKeys(result))

	// Trivy results are in "results" array
	results, ok := result["results"].([]interface{})
	if !ok {
		slog.Warn("saveTrivyFindings: results not found or wrong type", "result_keys", getMapKeys(result))
		return foundKeys
	}

	slog.Info("saveTrivyFindings: processing results", "count", len(results))

	for idx, r := range results {
		targetResult, ok := r.(map[string]interface{})
		if !ok {
			slog.Warn("saveTrivyFindings: result is not a map", "index", idx)
			continue
		}

		target := getStringValue(targetResult, "Target")
		vulns, ok := targetResult["Vulnerabilities"].([]interface{})
		if !ok {
			slog.Debug("saveTrivyFindings: no vulnerabilities in target", "target", target, "keys", getMapKeys(targetResult))
			continue
		}

		slog.Info("saveTrivyFindings: processing target", "target", target, "vuln_count", len(vulns))

		for _, v := range vulns {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			pkgName := getStringValue(vuln, "PkgName")
			installedVersion := getStringValue(vuln, "InstalledVersion")
			vulnID := getStringValue(vuln, "VulnerabilityID")

			primaryKey := database.GenerateSCAPrimaryKey(provider, repo, branch, commit, pkgName, installedVersion)
			foundKeys = append(foundKeys, primaryKey)

			finding := &database.SCAFinding{
				PrimaryUniqueKey: primaryKey,
				Provider:         provider,
				Repository:       repo,
				Branch:           branch,
				Commit:           commit,
				Package:          pkgName,
				InstalledVersion: installedVersion,
				FixedVersion:     getStringValue(vuln, "FixedVersion"),
				Severity:         getStringValue(vuln, "Severity"),
				VulnerabilityID:  vulnID,
				Title:            getStringValue(vuln, "Title"),
				Description:      getStringValue(vuln, "Description"),
				PkgPath:          target,
				DataSource:       "trivy",
				Status:           "open",
			}

			if err := db.UpsertSCAFinding(ctx, finding); err != nil {
				slog.Error("saveTrivyFindings: failed to upsert", "error", err, "vuln", vulnID)
			}
		}
	}

	slog.Info("saveTrivyFindings: completed", "saved_count", len(foundKeys))

	// Also save license findings from the same Trivy results
	saveTrivyLicenseFindings(ctx, db, result, provider, repo, branch, commit)

	return foundKeys
}

// saveTrivyLicenseFindings saves Trivy license findings to the database
func saveTrivyLicenseFindings(ctx context.Context, db database.DB, result map[string]interface{}, provider, repo, branch, commit string) {
	// Trivy results are in "results" array - each target may have Packages with Licenses
	results, ok := result["results"].([]interface{})
	if !ok {
		return
	}

	savedCount := 0
	for _, r := range results {
		targetResult, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		target := getStringValue(targetResult, "Target")
		pkgType := getStringValue(targetResult, "Type")

		// Check for Packages array (this contains license info)
		packages, ok := targetResult["Packages"].([]interface{})
		if !ok {
			continue
		}

		for _, p := range packages {
			pkg, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			pkgName := getStringValue(pkg, "Name")
			pkgVersion := getStringValue(pkg, "Version")

			// Licenses can be a string array
			licensesRaw, ok := pkg["Licenses"].([]interface{})
			if !ok || len(licensesRaw) == 0 {
				continue
			}

			for _, licRaw := range licensesRaw {
				license, ok := licRaw.(string)
				if !ok || license == "" {
					continue
				}

				// Classify the license
				classification := classifyLicense(license)
				severity := licenseSeverity(classification)

				primaryKey := database.GenerateLicensePrimaryKey(provider, repo, branch, commit, pkgName, pkgVersion, license)

				finding := &database.LicenseFinding{
					PrimaryUniqueKey: primaryKey,
					Provider:         provider,
					Repository:       repo,
					Branch:           branch,
					Commit:           commit,
					Package:          pkgName,
					Version:          pkgVersion,
					License:          license,
					Classification:   classification,
					PkgPath:          target,
					PkgType:          pkgType,
					Severity:         severity,
					Status:           "open",
				}

				if err := db.UpsertLicenseFinding(ctx, finding); err != nil {
					slog.Error("saveTrivyLicenseFindings: failed to upsert", "error", err, "pkg", pkgName, "license", license)
				} else {
					savedCount++
				}
			}
		}
	}

	if savedCount > 0 {
		slog.Info("saveTrivyLicenseFindings: completed", "saved_count", savedCount)
	}
}

// classifyLicense classifies a license into restricted, reciprocal, permissive, or unknown
func classifyLicense(license string) string {
	license = strings.ToLower(license)

	// Restricted licenses (copyleft, strong requirements)
	restrictedLicenses := []string{"gpl", "agpl", "lgpl", "sspl", "cc-by-nc", "cc-by-sa"}
	for _, r := range restrictedLicenses {
		if strings.Contains(license, r) {
			return "restricted"
		}
	}

	// Reciprocal licenses (some requirements)
	reciprocalLicenses := []string{"mpl", "cddl", "epl", "osl", "eupl"}
	for _, r := range reciprocalLicenses {
		if strings.Contains(license, r) {
			return "reciprocal"
		}
	}

	// Permissive licenses
	permissiveLicenses := []string{"mit", "apache", "bsd", "isc", "cc0", "unlicense", "wtfpl", "zlib", "public domain"}
	for _, p := range permissiveLicenses {
		if strings.Contains(license, p) {
			return "permissive"
		}
	}

	return "unknown"
}

// licenseSeverity returns a severity based on license classification
func licenseSeverity(classification string) string {
	switch classification {
	case "restricted":
		return "HIGH"
	case "reciprocal":
		return "MEDIUM"
	case "permissive":
		return "LOW"
	default:
		return "INFO"
	}
}

// saveSASTFindings saves OpenGrep/Semgrep SAST findings to the database
func saveSASTFindings(ctx context.Context, db database.DB, result map[string]interface{}, scanner, provider, repo, branch, commit string) []string {
	var foundKeys []string

	// OpenGrep/Semgrep results are in "findings" array
	findings, ok := result["findings"].([]interface{})
	if !ok {
		return foundKeys
	}

	for _, f := range findings {
		finding, ok := f.(map[string]interface{})
		if !ok {
			continue
		}

		checkID := getStringValue(finding, "check_id")
		fingerprint := getStringValue(finding, "extra.fingerprint")
		if fingerprint == "" {
			// Generate fingerprint from path + line if not present
			path := getStringValue(finding, "path")
			line := getIntValue(finding, "start.line")
			fingerprint = fmt.Sprintf("%s:%d", path, line)
		}

		primaryKey := database.GenerateSASTPrimaryKey(provider, repo, branch, commit, checkID, fingerprint)
		foundKeys = append(foundKeys, primaryKey)

		// Extract severity from extra.severity
		severity := getStringValue(finding, "extra.severity")
		if severity == "" {
			severity = "INFO"
		}

		// Extract category from check_id (e.g., "python.flask.security.injection" -> "security")
		category := extractCategory(checkID)

		dbFinding := &database.SASTFinding{
			PrimaryUniqueKey: primaryKey,
			Provider:         provider,
			Repository:       repo,
			Branch:           branch,
			Commit:           commit,
			Scanner:          scanner,
			CheckID:          checkID,
			Severity:         severity,
			Message:          getStringValue(finding, "extra.message"),
			FilePath:         getStringValue(finding, "path"),
			LineStart:        getIntValue(finding, "start.line"),
			LineEnd:          getIntValue(finding, "end.line"),
			ColStart:         getIntValue(finding, "start.col"),
			ColEnd:           getIntValue(finding, "end.col"),
			Fingerprint:      fingerprint,
			Category:         category,
			Status:           "open",
		}

		_ = db.UpsertSASTFinding(ctx, dbFinding)
	}

	return foundKeys
}

// saveSecretsFindings saves TruffleHog secrets findings to the database
func saveSecretsFindings(ctx context.Context, db database.DB, result map[string]interface{}, provider, repo, branch, commit string) []string {
	var foundKeys []string

	// TruffleHog results are in "findings" array
	findings, ok := result["findings"].([]interface{})
	if !ok {
		slog.Warn("saveSecretsFindings: findings not found or wrong type", "result_keys", getMapKeys(result))
		return foundKeys
	}

	slog.Info("saveSecretsFindings: processing findings", "count", len(findings))

	for i, f := range findings {
		finding, ok := f.(map[string]interface{})
		if !ok {
			slog.Warn("saveSecretsFindings: finding is not a map", "index", i, "type", fmt.Sprintf("%T", f))
			continue
		}

		detectorName := getStringValue(finding, "DetectorName")
		detectorType := getStringValue(finding, "DetectorType")

		// Create hashes for the credential and location (we don't store actual secrets)
		credentialHash := hashString(getStringValue(finding, "Raw"))

		// Try Filesystem first (for local path scans), then Git
		filePath := getStringValue(finding, "SourceMetadata.Data.Filesystem.file")
		if filePath == "" {
			filePath = getStringValue(finding, "SourceMetadata.Data.Git.file")
		}
		lineNumber := getIntValue(finding, "SourceMetadata.Data.Filesystem.line")
		if lineNumber == 0 {
			lineNumber = getIntValue(finding, "SourceMetadata.Data.Git.line")
		}

		// If file path is still empty, use detector name as fallback for identification
		if filePath == "" {
			filePath = "(no file path)"
		}

		locationHash := hashString(fmt.Sprintf("%s:%d", filePath, lineNumber))

		primaryKey := database.GenerateSecretsPrimaryKey(provider, repo, branch, commit, credentialHash, locationHash)
		foundKeys = append(foundKeys, primaryKey)

		verified := getBoolValue(finding, "Verified")
		severity := "HIGH"
		if verified {
			severity = "CRITICAL"
		}

		slog.Debug("saveSecretsFindings: saving finding",
			"index", i,
			"detector", detectorName,
			"verified", verified,
			"file", filePath,
			"line", lineNumber,
			"primaryKey", primaryKey)

		dbFinding := &database.SecretsFinding{
			PrimaryUniqueKey: primaryKey,
			Provider:         provider,
			Repository:       repo,
			Branch:           branch,
			Commit:           commit,
			DetectorName:     detectorName,
			DetectorType:     fmt.Sprintf("%v", detectorType),
			Verified:         verified,
			CredentialHash:   credentialHash,
			LocationHash:     locationHash,
			FilePath:         filePath,
			LineNumber:       lineNumber,
			Severity:         severity,
			Status:           "open",
		}

		if err := db.UpsertSecretsFinding(ctx, dbFinding); err != nil {
			slog.Error("saveSecretsFindings: failed to upsert", "error", err)
		}
	}

	slog.Info("saveSecretsFindings: completed", "saved_count", len(foundKeys))
	return foundKeys
}

// Helper functions for extracting values from result maps

func getStringValue(m map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := m

	for i, part := range parts {
		if i == len(parts)-1 {
			if v, ok := current[part].(string); ok {
				return v
			}
			return ""
		}
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	return ""
}

func getIntValue(m map[string]interface{}, path string) int {
	parts := strings.Split(path, ".")
	current := m

	for i, part := range parts {
		if i == len(parts)-1 {
			switch v := current[part].(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			}
			return 0
		}
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return 0
		}
	}
	return 0
}

func getBoolValue(m map[string]interface{}, path string) bool {
	parts := strings.Split(path, ".")
	current := m

	for i, part := range parts {
		if i == len(parts)-1 {
			if v, ok := current[part].(bool); ok {
				return v
			}
			return false
		}
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return false
		}
	}
	return false
}

func extractCategory(checkID string) string {
	// Extract category from check_id like "python.flask.security.injection"
	parts := strings.Split(checkID, ".")
	for _, p := range parts {
		if p == "security" || p == "correctness" || p == "performance" || p == "best-practice" {
			return p
		}
	}
	return "security" // default
}

func hashString(s string) string {
	if s == "" {
		return ""
	}
	// Simple hash for deduplication - not cryptographic
	h := 0
	for _, c := range s {
		h = 31*h + int(c)
	}
	return fmt.Sprintf("%x", h&0xffffffff)
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
