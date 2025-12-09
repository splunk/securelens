package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/splunk/securelens/cli/scan"
)

// ============================================================================
// Home View
// ============================================================================

func (m Model) viewHome() string {
	var b strings.Builder

	// Welcome message
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Welcome to SecureLens"))
	b.WriteString("\n")
	b.WriteString(SubtleStyle.Render("Security scanning made simple"))
	b.WriteString("\n\n")

	// Quick actions
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Quick Actions"))
	b.WriteString("\n\n")

	actions := []struct {
		key  string
		desc string
	}{
		{"2", "Browse & scan repositories"},
		{"3", "View scan results"},
		{"p", "Add provider (GitHub/GitLab/Bitbucket)"},
		{"?", "Show help"},
	}

	for _, action := range actions {
		keyStyle := lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true).
			Width(4)
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render("["+action.key+"]"), action.desc))
	}

	// Status
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Status"))
	b.WriteString("\n\n")

	// Provider summary
	providerCount := 0
	if m.config != nil {
		providerCount = len(m.config.Git.GitHub) + len(m.config.Git.GitLab) + len(m.config.Git.Bitbucket)
	}
	b.WriteString(fmt.Sprintf("  Configured providers: %d\n", providerCount))
	b.WriteString(fmt.Sprintf("  Discovered repos: %d\n", len(m.repos)))
	b.WriteString(fmt.Sprintf("  Scan mode: %s\n", m.scanMode))
	b.WriteString(fmt.Sprintf("  Saved reports: %d\n", len(m.reports)))

	return b.String()
}

func (m Model) updateHome(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "p":
		m.view = ViewWizard
		return m, nil
	}
	return m, nil
}

// ============================================================================
// Repos View (placeholder - will be expanded in Phase 2)
// ============================================================================

func (m Model) viewRepos() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Repository Browser"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString(m.spinner.View() + " Loading repositories...")
		return b.String()
	}

	if len(m.repos) == 0 {
		b.WriteString(SubtleStyle.Render("No repositories discovered yet."))
		b.WriteString("\n\n")
		b.WriteString("Press ")
		b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[r]"))
		b.WriteString(" to refresh/discover repositories")
		return b.String()
	}

	// Add repo URL input bar
	if m.addingRepoURL {
		inputStyle := lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorSuccess).
			Padding(0, 1)
		b.WriteString(inputStyle.Render("Add repo URL: " + m.repoURLInput + "█"))
		b.WriteString("\n")
		b.WriteString(HelpStyle.Render("Enter to add • Esc to cancel • Paste: https://github.com/owner/repo"))
		b.WriteString("\n\n")
	} else if m.searching {
		// Search bar
		searchStyle := lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)
		b.WriteString(searchStyle.Render("Search: " + m.searchFilter + "█"))
		b.WriteString("\n\n")
	} else if m.searchFilter != "" {
		b.WriteString(SubtleStyle.Render("Filter: \"" + m.searchFilter + "\""))
		b.WriteString(" ")
		b.WriteString(HelpStyle.Render("(press / to edit, esc to clear)"))
		b.WriteString("\n\n")
	}

	// Provider tabs
	tabs := []string{"All", "GitHub", "GitLab", "Bitbucket"}
	var tabsRendered []string
	for i, tab := range tabs {
		style := InactiveTabStyle
		if i == m.tabIndex {
			style = ActiveTabStyle
		}
		tabsRendered = append(tabsRendered, style.Render(" "+tab+" "))
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabsRendered...))

	// Show organization selector if on a provider-specific tab with multiple orgs
	orgs := m.getOrganizations()
	if m.tabIndex > 0 && len(orgs) > 0 {
		b.WriteString("  ")
		orgLabel := m.getCurrentOrg()
		orgStyle := lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)
		b.WriteString(orgStyle.Render("Org: " + orgLabel))
		if len(orgs) > 1 {
			b.WriteString(SubtleStyle.Render(fmt.Sprintf(" [%d orgs, ]/o to switch]", len(orgs))))
		}
	}
	b.WriteString("\n\n")

	// Filter repos by selected tab
	filteredRepos := m.filterReposByTab()

	// Calculate visible window (show 20 repos at a time, scrolling with cursor)
	pageSize := 20
	startIdx := 0
	if m.repoListIndex >= pageSize {
		startIdx = m.repoListIndex - pageSize + 1
	}
	endIdx := startIdx + pageSize
	if endIdx > len(filteredRepos) {
		endIdx = len(filteredRepos)
	}

	// Show scroll indicator if there are items above
	if startIdx > 0 {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↑ %d more above\n", startIdx)))
	}

	// Show repo list
	for i := startIdx; i < endIdx; i++ {
		repo := filteredRepos[i]
		prefix := "  "
		if i == m.repoListIndex {
			prefix = "> "
		}

		// Selection indicator
		selected := ""
		if m.selected[i] {
			selected = SuccessStyle.Render("[✓] ")
		} else {
			selected = "[ ] "
		}

		// Provider badge
		providerBadge := ""
		if len(repo.Provider) >= 2 {
			providerBadge = ProviderStyle(repo.Provider).Render(repo.Provider[:2])
		} else {
			providerBadge = ProviderStyle(repo.Provider).Render(repo.Provider)
		}

		// Source indicator for manual repos
		sourceTag := ""
		if repo.Source == "manual" {
			sourceTag = lipgloss.NewStyle().Foreground(ColorSuccess).Render(" [manual]")
		}

		// Visibility
		vis := ""
		if repo.IsPrivate {
			vis = SubtleStyle.Render(" (private)")
		}

		line := fmt.Sprintf("%s%s%s %s%s%s", prefix, selected, providerBadge, repo.FullName, vis, sourceTag)
		if i == m.repoListIndex {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	// Show scroll indicator if there are items below
	if endIdx < len(filteredRepos) {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↓ %d more below\n", len(filteredRepos)-endIdx)))
	}

	// Footer hints
	b.WriteString("\n")
	footerText := "/: search • +: add URL • space: select • enter: scan • r: refresh"
	if m.hasMoreRepos {
		footerText += " • m: load more"
	}
	// Show org switching hint if on a provider tab with multiple orgs
	if m.tabIndex > 0 && len(orgs) > 1 {
		footerText += " • ]/o: next org"
	}
	b.WriteString(HelpStyle.Render(footerText))

	// Show repo count
	b.WriteString("\n")
	var countText string
	if m.searchFilter != "" {
		countText = fmt.Sprintf("Showing %d of %d repos (filtered)", len(filteredRepos), len(m.repos))
	} else {
		countText = fmt.Sprintf("%d repos", len(m.repos))
	}
	if m.hasMoreRepos {
		countText += " (more available)"
	}
	// Show which provider the repos were loaded from
	if m.loadedProvider != "" {
		countText += fmt.Sprintf(" [%s]", m.loadedProvider)
	}
	b.WriteString(SubtleStyle.Render(countText))

	return b.String()
}

// reloadIfNeeded checks if repos need to be reloaded based on the current tab
// and triggers a reload if the loaded provider doesn't match the selected tab
func (m Model) reloadIfNeeded() (tea.Model, tea.Cmd) {
	targetProvider := m.getProviderFilter()

	// If we're on "All" tab and repos were loaded for a specific provider, reload
	// If we're on a specific provider tab and repos were loaded for a different provider (or all), reload
	if targetProvider != m.loadedProvider {
		m.repoLoadCount = 0 // Reset pagination
		m.hasMoreRepos = true
		m.loading = true
		m.repos = nil // Clear existing repos
		m.selected = make(map[int]bool)
		m.statusMsg = "Loading repositories..."
		return m, m.loadRepos()
	}
	return m, nil
}

// parseRepoURL parses a repository URL and creates a DiscoveredRepository
// Supports formats: https://github.com/owner/repo, https://gitlab.com/owner/repo, etc.
func (m Model) parseRepoURL(urlStr string) *scan.DiscoveredRepository {
	urlStr = strings.TrimSpace(urlStr)
	urlStr = strings.TrimSuffix(urlStr, ".git")

	// Detect provider and parse
	var provider, owner, repo string

	if strings.Contains(urlStr, "github.com") {
		provider = "github"
		parts := strings.Split(urlStr, "github.com/")
		if len(parts) < 2 {
			return nil
		}
		pathParts := strings.Split(strings.Trim(parts[1], "/"), "/")
		if len(pathParts) < 2 {
			return nil
		}
		owner = pathParts[0]
		repo = pathParts[1]
	} else if strings.Contains(urlStr, "gitlab") {
		provider = "gitlab"
		// Handle both gitlab.com and self-hosted gitlab instances
		parts := strings.SplitN(urlStr, "://", 2)
		if len(parts) < 2 {
			return nil
		}
		pathWithHost := parts[1]
		// Remove host part
		hostParts := strings.SplitN(pathWithHost, "/", 2)
		if len(hostParts) < 2 {
			return nil
		}
		pathParts := strings.Split(strings.Trim(hostParts[1], "/"), "/")
		if len(pathParts) < 2 {
			return nil
		}
		owner = pathParts[0]
		repo = pathParts[1]
	} else if strings.Contains(urlStr, "bitbucket") {
		provider = "bitbucket"
		parts := strings.SplitN(urlStr, "://", 2)
		if len(parts) < 2 {
			return nil
		}
		pathWithHost := parts[1]
		hostParts := strings.SplitN(pathWithHost, "/", 2)
		if len(hostParts) < 2 {
			return nil
		}
		pathParts := strings.Split(strings.Trim(hostParts[1], "/"), "/")
		if len(pathParts) < 2 {
			return nil
		}
		owner = pathParts[0]
		repo = pathParts[1]
	} else {
		return nil
	}

	fullName := owner + "/" + repo
	cloneURL := urlStr
	if !strings.HasSuffix(cloneURL, ".git") {
		cloneURL += ".git"
	}

	return &scan.DiscoveredRepository{
		Provider:  provider,
		Name:      repo,
		FullName:  fullName,
		URL:       cloneURL,
		IsPrivate: false, // Assume public, will be determined on scan
		Source:    "manual",
	}
}

func (m Model) filterReposByTab() []scan.DiscoveredRepository {
	var filtered []scan.DiscoveredRepository

	providers := []string{"", "github", "gitlab", "bitbucket"}
	targetProvider := providers[m.tabIndex]

	searchLower := strings.ToLower(m.searchFilter)

	for _, repo := range m.repos {
		// Filter by provider tab (unless "All" is selected)
		if m.tabIndex != 0 && repo.Provider != targetProvider {
			continue
		}

		// Filter by search term (case-insensitive substring match)
		if m.searchFilter != "" {
			nameLower := strings.ToLower(repo.FullName)
			descLower := strings.ToLower(repo.Description)
			if !strings.Contains(nameLower, searchLower) && !strings.Contains(descLower, searchLower) {
				continue
			}
		}

		filtered = append(filtered, repo)
	}
	return filtered
}

func (m Model) updateRepos(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle add repo URL mode
	if m.addingRepoURL {
		switch msg.Type {
		case tea.KeyEsc:
			m.addingRepoURL = false
			m.repoURLInput = ""
			return m, nil
		case tea.KeyEnter:
			// Parse the URL and add to repos list
			if m.repoURLInput != "" {
				repo := m.parseRepoURL(m.repoURLInput)
				if repo != nil {
					// Add to manualRepos (persists across reloads) AND to repos (for immediate display)
					m.manualRepos = append([]scan.DiscoveredRepository{*repo}, m.manualRepos...)
					m.repos = append([]scan.DiscoveredRepository{*repo}, m.repos...)
					m.repoListIndex = 0
					m.statusMsg = "Added: " + repo.FullName
				} else {
					m.statusMsg = "Invalid URL format. Use: https://github.com/owner/repo"
				}
			}
			m.addingRepoURL = false
			m.repoURLInput = ""
			return m, nil
		case tea.KeyBackspace:
			if len(m.repoURLInput) > 0 {
				m.repoURLInput = m.repoURLInput[:len(m.repoURLInput)-1]
			}
			return m, nil
		default:
			if msg.Type == tea.KeyRunes {
				m.repoURLInput += string(msg.Runes)
			}
			return m, nil
		}
	}

	// Handle search mode input
	if m.searching {
		switch msg.Type {
		case tea.KeyEsc:
			m.searching = false
			return m, nil
		case tea.KeyEnter:
			m.searching = false
			m.repoListIndex = 0
			return m, nil
		case tea.KeyBackspace:
			if len(m.searchFilter) > 0 {
				m.searchFilter = m.searchFilter[:len(m.searchFilter)-1]
				m.repoListIndex = 0
			}
			return m, nil
		default:
			if msg.Type == tea.KeyRunes {
				m.searchFilter += string(msg.Runes)
				m.repoListIndex = 0
			}
			return m, nil
		}
	}

	filteredRepos := m.filterReposByTab()

	switch {
	case key.Matches(msg, m.keys.AddRepoURL):
		m.addingRepoURL = true
		m.repoURLInput = ""
		return m, nil
	case key.Matches(msg, m.keys.Search):
		m.searching = true
		return m, nil
	case key.Matches(msg, m.keys.Escape):
		// Clear search filter if set
		if m.searchFilter != "" {
			m.searchFilter = ""
			m.repoListIndex = 0
			return m, nil
		}
	case key.Matches(msg, m.keys.Up):
		if m.repoListIndex > 0 {
			m.repoListIndex--
		}
	case key.Matches(msg, m.keys.Down):
		if m.repoListIndex < len(filteredRepos)-1 {
			m.repoListIndex++
		}
	case key.Matches(msg, m.keys.Space):
		m.selected[m.repoListIndex] = !m.selected[m.repoListIndex]
	case key.Matches(msg, m.keys.SelectAll):
		for i := range filteredRepos {
			m.selected[i] = true
		}
	case key.Matches(msg, m.keys.SelectNone):
		m.selected = make(map[int]bool)
	case key.Matches(msg, m.keys.Tab):
		oldTab := m.tabIndex
		m.tabIndex = (m.tabIndex + 1) % 4
		m.repoListIndex = 0
		m.orgIndex = 0 // Reset org index when changing tabs
		// Reload repos if tab changed and we're switching to/from a specific provider
		if oldTab != m.tabIndex {
			return m.reloadIfNeeded()
		}
	case key.Matches(msg, m.keys.ShiftTab):
		oldTab := m.tabIndex
		m.tabIndex = (m.tabIndex + 3) % 4 // +3 is same as -1 mod 4
		m.repoListIndex = 0
		m.orgIndex = 0 // Reset org index when changing tabs
		// Reload repos if tab changed
		if oldTab != m.tabIndex {
			return m.reloadIfNeeded()
		}
	case key.Matches(msg, m.keys.NextOrg):
		// Cycle to next organization
		orgs := m.getOrganizations()
		if len(orgs) > 0 {
			m.orgIndex = (m.orgIndex + 1) % (len(orgs) + 1) // +1 for "All"
			m.repoListIndex = 0
			m.repoLoadCount = 0
			m.hasMoreRepos = true
			m.loading = true
			m.repos = nil
			m.selected = make(map[int]bool)
			return m, m.loadRepos()
		}
	case key.Matches(msg, m.keys.PrevOrg):
		// Cycle to previous organization
		orgs := m.getOrganizations()
		if len(orgs) > 0 {
			m.orgIndex = (m.orgIndex + len(orgs)) % (len(orgs) + 1) // +len for wrap-around
			m.repoListIndex = 0
			m.repoLoadCount = 0
			m.hasMoreRepos = true
			m.loading = true
			m.repos = nil
			m.selected = make(map[int]bool)
			return m, m.loadRepos()
		}
	case key.Matches(msg, m.keys.Refresh):
		m.repoLoadCount = 0 // Reset pagination on refresh
		m.hasMoreRepos = true
		m.loading = true
		return m, m.loadRepos()
	case key.Matches(msg, m.keys.LoadMore):
		if m.hasMoreRepos && !m.loading {
			m.loading = true
			m.statusMsg = "Loading more repositories..."
			return m, m.loadRepos()
		}
	case key.Matches(msg, m.keys.Enter):
		// Start scan with selected repos
		var toScan []scan.DiscoveredRepository
		for i, selected := range m.selected {
			if selected && i < len(filteredRepos) {
				toScan = append(toScan, filteredRepos[i])
			}
		}
		if len(toScan) == 0 && m.repoListIndex < len(filteredRepos) {
			toScan = append(toScan, filteredRepos[m.repoListIndex])
		}
		if len(toScan) > 0 {
			m.view = ViewScan
			return m, func() tea.Msg {
				return ScanStartMsg{Repos: toScan}
			}
		}
	}

	return m, nil
}

// ============================================================================
// Scan View (placeholder - will be expanded in Phase 3)
// ============================================================================

func (m Model) viewScan() string {
	var b strings.Builder

	b.WriteString("\n")

	// Show error if any
	if m.err != nil {
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(ColorError).Render("Scan Failed"))
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("Error: " + m.err.Error()))
		b.WriteString("\n\n")
		b.WriteString(HelpStyle.Render("Press esc to go back • r to retry"))
		return b.String()
	}

	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Scanning..."))
	b.WriteString("\n\n")

	b.WriteString(m.spinner.View() + " Running security scans...")
	b.WriteString("\n\n")

	// Scanner status (placeholder)
	scanners := []struct {
		name   string
		status string
	}{
		{"opengrep", "running"},
		{"trivy", "pending"},
		{"trufflehog", "pending"},
	}

	for _, s := range scanners {
		var statusIcon string
		switch s.status {
		case "running":
			statusIcon = m.spinner.View()
		case "complete":
			statusIcon = SuccessStyle.Render("✓")
		case "error":
			statusIcon = ErrorStyle.Render("✗")
		default:
			statusIcon = SubtleStyle.Render("○")
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", statusIcon, s.name))
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Press esc to cancel"))

	return b.String()
}

func (m Model) updateScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Escape):
		m.err = nil // Clear error when going back
		m.view = ViewRepos
		return m, nil
	case key.Matches(msg, m.keys.Refresh):
		// Retry scan if there was an error
		if m.err != nil {
			m.err = nil
			m.loading = true
			m.statusMsg = "Retrying scan..."
			// Re-scan the currently selected repos
			filteredRepos := m.filterReposByTab()
			var toScan []scan.DiscoveredRepository
			for i, selected := range m.selected {
				if selected && i < len(filteredRepos) {
					toScan = append(toScan, filteredRepos[i])
				}
			}
			if len(toScan) == 0 && m.repoListIndex < len(filteredRepos) {
				toScan = append(toScan, filteredRepos[m.repoListIndex])
			}
			if len(toScan) > 0 {
				return m, func() tea.Msg {
					return ScanStartMsg{Repos: toScan}
				}
			}
		}
	}
	return m, nil
}

// ============================================================================
// Results View - Report Browser with Hierarchical Navigation
// ============================================================================

func (m Model) viewResults() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Scan Results"))
	b.WriteString("\n\n")

	// If we're viewing a specific report, show the report details
	if m.currentReport != nil {
		return m.viewReportDetail()
	}

	// Show loading state
	if m.loading {
		b.WriteString(m.spinner.View() + " Loading reports...")
		return b.String()
	}

	// Show breadcrumb navigation
	breadcrumb := m.getBreadcrumb()
	levelName := m.getLevelName()
	b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Render(breadcrumb))
	b.WriteString("\n")
	b.WriteString(SubtleStyle.Render("Browsing: " + levelName))
	b.WriteString("\n\n")

	// Show items at current level
	if len(m.reportBrowserItems) == 0 {
		b.WriteString(SubtleStyle.Render("No reports found."))
		b.WriteString("\n\n")
		b.WriteString("Run a scan with ")
		b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("--debug"))
		b.WriteString(" to save reports:")
		b.WriteString("\n")
		b.WriteString(HelpStyle.Render("  securelens scan repo --local-path . --mode standalone --debug"))
		return b.String()
	}

	// Calculate visible window (show 15 items at a time)
	pageSize := 15
	startIdx := 0
	if m.reportListIndex >= pageSize {
		startIdx = m.reportListIndex - pageSize + 1
	}
	endIdx := startIdx + pageSize
	if endIdx > len(m.reportBrowserItems) {
		endIdx = len(m.reportBrowserItems)
	}

	// Show scroll indicator if there are items above
	if startIdx > 0 {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↑ %d more above\n", startIdx)))
	}

	// Show items list
	for i := startIdx; i < endIdx; i++ {
		item := m.reportBrowserItems[i]
		prefix := "  "
		if i == m.reportListIndex {
			prefix = "> "
		}

		var line string
		if item.IsDir {
			// Directory with icon and child count
			icon := m.getDirIcon()
			childInfo := ""
			if item.Children > 0 {
				childInfo = SubtleStyle.Render(fmt.Sprintf(" (%d)", item.Children))
			}
			line = fmt.Sprintf("%s%s %s%s", prefix, icon, item.Name, childInfo)
		} else {
			// Report file
			icon := "📄"
			line = fmt.Sprintf("%s%s %s", prefix, icon, item.Name)
		}

		if i == m.reportListIndex {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	// Show scroll indicator if there are items below
	if endIdx < len(m.reportBrowserItems) {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↓ %d more below\n", len(m.reportBrowserItems)-endIdx)))
	}

	// Footer hints
	b.WriteString("\n")
	if len(m.reportBrowserPath) > 0 {
		b.WriteString(HelpStyle.Render("enter: open • backspace/esc: go back • r: refresh"))
	} else {
		b.WriteString(HelpStyle.Render("enter: open • r: refresh"))
	}

	return b.String()
}

// viewReportDetail renders the detailed view of a loaded report
func (m Model) viewReportDetail() string {
	var b strings.Builder

	report := m.currentReport

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Scan Results"))
	b.WriteString("\n")
	// Show saved path with highlight if available
	if m.currentReportPath != "" {
		savedStyle := lipgloss.NewStyle().Foreground(ColorSuccess)
		b.WriteString(savedStyle.Render("Saved to: "))
		b.WriteString(SubtleStyle.Render(m.currentReportPath))
	}
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("Repository: %s\n", report.Repository))
	b.WriteString(fmt.Sprintf("Branch:     %s\n", report.Branch))
	b.WriteString(fmt.Sprintf("Commit:     %s\n", report.Commit))
	b.WriteString(fmt.Sprintf("Timestamp:  %s\n", report.Timestamp))
	b.WriteString(fmt.Sprintf("Status:     %s\n", report.Status))
	b.WriteString("\n")

	// Results table header
	b.WriteString("┌────────────┬──────────┬───────────────────┬─────────────┐\n")
	b.WriteString("│  SCANNER   │  STATUS  │     FINDINGS      │ BY SEVERITY │\n")
	b.WriteString("├────────────┼──────────┼───────────────────┼─────────────┤\n")

	for _, scanner := range report.Scanners {
		status := "complete"
		findings := "-"
		severityStr := "-"
		if result, ok := report.Results[scanner].(map[string]interface{}); ok {
			if s, exists := result["status"]; exists {
				status = fmt.Sprintf("%v", s)
			}
			if fc, exists := result["findings_count"]; exists {
				findings = fmt.Sprintf("%v findings", fc)
			} else if vc, exists := result["vulnerabilities_count"]; exists {
				findings = fmt.Sprintf("%v vulns", vc)
			}
			severityStr = scan.ExtractSeveritySummary(result)
		}
		b.WriteString(fmt.Sprintf("│ %-10s │ %-8s │ %-17s │ %-11s │\n",
			scanner, status, findings, severityStr))
	}

	b.WriteString("└────────────┴──────────┴───────────────────┴─────────────┘\n")

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("backspace/esc: back to browser"))

	return b.String()
}

// getLevelName returns a human-readable name for the current browser level
func (m Model) getLevelName() string {
	level := m.getCurrentBrowserLevel()
	switch level {
	case ReportLevelOwner:
		return "Organizations/Owners"
	case ReportLevelRepo:
		return "Repositories"
	case ReportLevelBranch:
		return "Branches"
	case ReportLevelCommit:
		return "Commits"
	case ReportLevelReport:
		return "Reports"
	default:
		return "Reports"
	}
}

// getDirIcon returns an appropriate icon for the current level
func (m Model) getDirIcon() string {
	level := m.getCurrentBrowserLevel()
	switch level {
	case ReportLevelOwner:
		return "🏢"
	case ReportLevelRepo:
		return "📁"
	case ReportLevelBranch:
		return "🌿"
	case ReportLevelCommit:
		return "📝"
	default:
		return "📂"
	}
}

func (m Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// If viewing a report detail, handle back navigation
	if m.currentReport != nil {
		switch {
		case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Escape), msg.Type == tea.KeyBackspace:
			m.currentReport = nil
			m.currentReportPath = ""
			return m, nil
		}
		return m, nil
	}

	// Browser navigation
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.reportListIndex > 0 {
			m.reportListIndex--
		}
	case key.Matches(msg, m.keys.Down):
		if m.reportListIndex < len(m.reportBrowserItems)-1 {
			m.reportListIndex++
		}
	case key.Matches(msg, m.keys.Enter):
		// Navigate into directory or open report
		if m.reportListIndex < len(m.reportBrowserItems) {
			item := m.reportBrowserItems[m.reportListIndex]
			if item.IsDir {
				// Navigate into directory
				m.reportBrowserPath = append(m.reportBrowserPath, item.Name)
				m.reportListIndex = 0
				m.loading = true
				return m, m.loadReportBrowserItems()
			} else {
				// Load and display report
				m.loading = true
				return m, m.loadReportDetail(item.Path)
			}
		}
	case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Escape), msg.Type == tea.KeyBackspace:
		// Navigate up one level
		if len(m.reportBrowserPath) > 0 {
			m.reportBrowserPath = m.reportBrowserPath[:len(m.reportBrowserPath)-1]
			m.reportListIndex = 0
			m.loading = true
			return m, m.loadReportBrowserItems()
		}
	case key.Matches(msg, m.keys.Refresh):
		m.loading = true
		return m, m.loadReportBrowserItems()
	}

	return m, nil
}

// ============================================================================
// Wizard View (placeholder - will be expanded in Phase 5)
// ============================================================================

func (m Model) viewWizard() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Add Git Provider"))
	b.WriteString("\n\n")

	b.WriteString("Select provider type:\n\n")

	providers := []struct {
		key  string
		name string
	}{
		{"1", "GitHub"},
		{"2", "GitLab"},
		{"3", "Bitbucket"},
	}

	for _, p := range providers {
		keyStyle := lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true).
			Width(4)
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render("["+p.key+"]"), p.name))
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Press esc to cancel"))

	return b.String()
}

func (m Model) updateWizard(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Escape):
		m.view = ViewHome
	}
	return m, nil
}
