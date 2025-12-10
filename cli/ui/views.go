package ui

import (
	"context"
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
		{"4", "Vulnerability database"},
		{"5", "License findings"},
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
		b.WriteString("\n")
		b.WriteString(HelpStyle.Render("Enter: search API • Esc: cancel • Type to filter locally"))
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
			// If search term has 2+ chars, trigger API search
			if len(m.searchFilter) >= 2 {
				m.loading = true
				m.statusMsg = "Searching for \"" + m.searchFilter + "\"..."
				return m, m.searchRepos(m.searchFilter)
			}
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
		m.statusMsg = "Refreshing from API..."
		return m, m.refreshReposFromAPI()
	case key.Matches(msg, m.keys.LoadMore):
		if m.hasMoreRepos && !m.loading {
			m.loading = true
			m.statusMsg = "Loading more repositories..."
			return m, m.loadRepos()
		}
	case key.Matches(msg, m.keys.Enter):
		// Get selected repo(s) and go to branch selection
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
			// Queue all repos for branch selection, process first one
			m.repoQueue = toScan[1:] // Remaining repos go to queue
			repo := toScan[0]
			m.loading = true
			m.statusMsg = fmt.Sprintf("Loading branches for %s... (%d repos queued)", repo.FullName, len(m.repoQueue))
			return m, m.loadBranches(repo)
		}
	}

	return m, nil
}

// ============================================================================
// Branch Selection View
// ============================================================================

func (m Model) viewBranchSelect() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Select Branches to Scan"))
	b.WriteString("\n\n")

	// Show repo info with queue status
	b.WriteString(fmt.Sprintf("Repository: %s\n", m.branchSelectRepo.FullName))
	b.WriteString(fmt.Sprintf("Provider:   %s\n", m.branchSelectRepo.Provider))
	if len(m.repoQueue) > 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Render(
			fmt.Sprintf("Queue:      %d more repo(s) after this\n", len(m.repoQueue))))
	}
	if len(m.scanItems) > 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorSuccess).Render(
			fmt.Sprintf("Scans:      %d scan(s) queued\n", len(m.scanItems))))
	}
	b.WriteString("\n")

	if m.loading {
		b.WriteString(m.spinner.View() + " Loading branches...")
		return b.String()
	}

	if len(m.branchSelectBranches) == 0 {
		b.WriteString(SubtleStyle.Render("No branches found. Using default branch."))
		b.WriteString("\n\n")
		b.WriteString(HelpStyle.Render("Press enter to scan main branch • esc to go back"))
		return b.String()
	}

	// Show search bar
	if m.branchSearching {
		searchStyle := lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)
		b.WriteString(searchStyle.Render("Search: " + m.branchSearch + "█"))
		b.WriteString("\n")
		b.WriteString(HelpStyle.Render("Enter to confirm • Esc to cancel"))
		b.WriteString("\n\n")
	} else if m.branchSearch != "" {
		b.WriteString(SubtleStyle.Render("Filter: \"" + m.branchSearch + "\""))
		b.WriteString(" ")
		b.WriteString(HelpStyle.Render("(press / to edit, esc to clear)"))
		b.WriteString("\n\n")
	}

	// Show selected count
	selectedCount := 0
	for _, selected := range m.branchSelected {
		if selected {
			selectedCount++
		}
	}
	b.WriteString(fmt.Sprintf("Select branches to scan (%d selected):\n\n", selectedCount))

	// Filter branches by search term
	filteredBranches := m.filterBranchesBySearch()

	// Calculate visible window (show 15 branches at a time)
	pageSize := 15
	startIdx := 0
	if m.branchSelectIndex >= pageSize {
		startIdx = m.branchSelectIndex - pageSize + 1
	}
	endIdx := startIdx + pageSize
	if endIdx > len(filteredBranches) {
		endIdx = len(filteredBranches)
	}

	// Show scroll indicator if there are items above
	if startIdx > 0 {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↑ %d more above\n", startIdx)))
	}

	// Show branch list
	for i := startIdx; i < endIdx; i++ {
		branch := filteredBranches[i]
		prefix := "  "
		if i == m.branchSelectIndex {
			prefix = "> "
		}

		// Selection indicator
		selected := ""
		if m.branchSelected[i] {
			selected = SuccessStyle.Render("[✓] ")
		} else {
			selected = "[ ] "
		}

		// Highlight common branches
		branchDisplay := branch
		if branch == "main" || branch == "master" {
			branchDisplay = lipgloss.NewStyle().Bold(true).Render(branch) + SubtleStyle.Render(" (default)")
		}

		line := fmt.Sprintf("%s%s%s", prefix, selected, branchDisplay)
		if i == m.branchSelectIndex {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	// Show scroll indicator if there are items below
	if endIdx < len(filteredBranches) {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↓ %d more below\n", len(filteredBranches)-endIdx)))
	}

	// Footer hints
	b.WriteString("\n")
	if len(m.repoQueue) > 0 {
		b.WriteString(HelpStyle.Render("/: search • space: toggle • a: all • n: none • enter: next repo • esc: cancel all"))
	} else {
		b.WriteString(HelpStyle.Render("/: search • space: toggle • a: all • n: none • enter: start scanning • esc: back"))
	}

	// Show branch count
	if m.branchSearch != "" {
		b.WriteString("\n")
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("Showing %d of %d branches (filtered)", len(filteredBranches), len(m.branchSelectBranches))))
	}

	return b.String()
}

// filterBranchesBySearch returns branches filtered by the search term
func (m Model) filterBranchesBySearch() []string {
	if m.branchSearch == "" {
		return m.branchSelectBranches
	}

	searchLower := strings.ToLower(m.branchSearch)
	var filtered []string
	for _, branch := range m.branchSelectBranches {
		if strings.Contains(strings.ToLower(branch), searchLower) {
			filtered = append(filtered, branch)
		}
	}
	return filtered
}

func (m Model) updateBranchSelect(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle search mode input first
	if m.branchSearching {
		switch msg.Type {
		case tea.KeyEsc:
			m.branchSearching = false
			return m, nil
		case tea.KeyEnter:
			m.branchSearching = false
			m.branchSelectIndex = 0
			return m, nil
		case tea.KeyBackspace:
			if len(m.branchSearch) > 0 {
				m.branchSearch = m.branchSearch[:len(m.branchSearch)-1]
				m.branchSelectIndex = 0
			}
			return m, nil
		default:
			if msg.Type == tea.KeyRunes {
				m.branchSearch += string(msg.Runes)
				m.branchSelectIndex = 0
			}
			return m, nil
		}
	}

	// Get filtered branches for navigation bounds
	filteredBranches := m.filterBranchesBySearch()

	switch {
	case key.Matches(msg, m.keys.Search):
		m.branchSearching = true
		return m, nil

	case key.Matches(msg, m.keys.Escape):
		// Clear search filter if set, otherwise go back
		if m.branchSearch != "" {
			m.branchSearch = ""
			m.branchSelectIndex = 0
			return m, nil
		}
		// Clear all queues and go back
		m.repoQueue = nil
		m.scanItems = nil
		m.view = ViewRepos
		return m, nil

	case key.Matches(msg, m.keys.Up):
		if m.branchSelectIndex > 0 {
			m.branchSelectIndex--
		}

	case key.Matches(msg, m.keys.Down):
		if m.branchSelectIndex < len(filteredBranches)-1 {
			m.branchSelectIndex++
		}

	case key.Matches(msg, m.keys.Space):
		// Toggle selection using filtered branch index
		if m.branchSelectIndex < len(filteredBranches) {
			// Find the original index for this branch
			branch := filteredBranches[m.branchSelectIndex]
			for origIdx, origBranch := range m.branchSelectBranches {
				if origBranch == branch {
					m.branchSelected[origIdx] = !m.branchSelected[origIdx]
					break
				}
			}
		}

	case key.Matches(msg, m.keys.SelectAll):
		// Select all filtered branches
		for _, branch := range filteredBranches {
			for origIdx, origBranch := range m.branchSelectBranches {
				if origBranch == branch {
					m.branchSelected[origIdx] = true
					break
				}
			}
		}

	case key.Matches(msg, m.keys.SelectNone):
		m.branchSelected = make(map[int]bool)

	case key.Matches(msg, m.keys.Enter):
		// Build scan items from selected branches
		var selectedBranches []string
		for i, selected := range m.branchSelected {
			if selected && i < len(m.branchSelectBranches) {
				selectedBranches = append(selectedBranches, m.branchSelectBranches[i])
			}
		}
		// If nothing selected, use the highlighted branch from filtered list
		if len(selectedBranches) == 0 {
			if m.branchSelectIndex < len(filteredBranches) {
				selectedBranches = append(selectedBranches, filteredBranches[m.branchSelectIndex])
			} else if len(filteredBranches) > 0 {
				selectedBranches = append(selectedBranches, filteredBranches[0])
			} else {
				selectedBranches = append(selectedBranches, "main")
			}
		}

		// Add to scan items list with pending status
		for _, branch := range selectedBranches {
			m.scanItems = append(m.scanItems, ScanItem{
				Repo:   m.branchSelectRepo,
				Branch: branch,
				Status: ScanStatusPending,
			})
		}

		// If there are more repos in the queue, go to next repo's branch selection
		if len(m.repoQueue) > 0 {
			nextRepo := m.repoQueue[0]
			m.repoQueue = m.repoQueue[1:]
			m.loading = true
			m.statusMsg = fmt.Sprintf("Loading branches for %s... (%d repos remaining)", nextRepo.FullName, len(m.repoQueue))
			return m, m.loadBranches(nextRepo)
		}

		// No more repos - start scanning
		if len(m.scanItems) > 0 {
			m.view = ViewScan
			m.currentScanIdx = 0
			m.scanItems[0].Status = ScanStatusRunning
			m.loading = true
			item := m.scanItems[0]
			m.statusMsg = fmt.Sprintf("Scanning %s @ %s...", item.Repo.FullName, item.Branch)
			return m, m.runScanWithBranch(item.Repo, item.Branch)
		}
	}

	return m, nil
}

// ============================================================================
// Scan View - Shows progress of all repo/branch scans
// ============================================================================

func (m Model) viewScan() string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Scan Progress"))
	b.WriteString("\n\n")

	// Count stats
	pending, running, completed, failed := 0, 0, 0, 0
	for _, item := range m.scanItems {
		switch item.Status {
		case ScanStatusPending:
			pending++
		case ScanStatusRunning:
			running++
		case ScanStatusComplete:
			completed++
		case ScanStatusError:
			failed++
		}
	}

	// Summary line
	total := len(m.scanItems)
	if running > 0 {
		b.WriteString(m.spinner.View() + " ")
	}
	summaryStyle := lipgloss.NewStyle().Bold(true)
	b.WriteString(summaryStyle.Render(fmt.Sprintf("Scanning %d repo/branch combinations", total)))
	b.WriteString("\n")
	// Show running count between completed and pending for clarity
	runningStr := ""
	if running > 0 {
		runningStr = fmt.Sprintf("  Running: %s", lipgloss.NewStyle().Foreground(ColorPrimary).Render(fmt.Sprintf("%d", running)))
	}
	b.WriteString(fmt.Sprintf("  Completed: %s%s  Pending: %s  Failed: %s\n\n",
		SuccessStyle.Render(fmt.Sprintf("%d", completed)),
		runningStr,
		SubtleStyle.Render(fmt.Sprintf("%d", pending)),
		ErrorStyle.Render(fmt.Sprintf("%d", failed))))

	// Calculate visible window (show ~10 items at a time)
	pageSize := 10
	startIdx := 0
	if m.scanListIndex >= pageSize {
		startIdx = m.scanListIndex - pageSize + 1
	}
	endIdx := startIdx + pageSize
	if endIdx > len(m.scanItems) {
		endIdx = len(m.scanItems)
	}

	// Show scan items as a simple list
	for i := startIdx; i < endIdx; i++ {
		item := m.scanItems[i]

		// Status icon
		var statusIcon string
		switch item.Status {
		case ScanStatusPending:
			statusIcon = SubtleStyle.Render("○")
		case ScanStatusRunning:
			statusIcon = m.spinner.View()
		case ScanStatusComplete:
			statusIcon = SuccessStyle.Render("✓")
		case ScanStatusError:
			statusIcon = ErrorStyle.Render("✗")
		}

		// Cursor indicator
		cursor := "  "
		if i == m.currentScanIdx {
			cursor = "> "
		}

		// Build the line
		repoName := item.Repo.FullName
		branchName := item.Branch

		// First line: status, repo, branch
		line := fmt.Sprintf("%s%s %s @ %s", cursor, statusIcon, repoName, branchName)
		b.WriteString(line + "\n")

		// Second line: report path or error (indented)
		if item.Status == ScanStatusComplete && item.ReportPath != "" {
			b.WriteString(fmt.Sprintf("      %s\n", SubtleStyle.Render(item.ReportPath)))
		} else if item.Status == ScanStatusError && item.Error != "" {
			b.WriteString(fmt.Sprintf("      %s\n", ErrorStyle.Render(item.Error)))
		}
	}

	// Show scroll indicator
	if endIdx < len(m.scanItems) {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("  ↓ %d more below\n", len(m.scanItems)-endIdx)))
	}

	// Show scanner logs if any
	if len(m.scanLogs) > 0 {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).Render("─── Scanner Output ───"))
		b.WriteString("\n")
		logStyle := lipgloss.NewStyle().Foreground(ColorMuted)
		for _, log := range m.scanLogs {
			b.WriteString(logStyle.Render("  " + log))
			b.WriteString("\n")
		}
	}

	// Footer
	b.WriteString("\n")
	if running > 0 {
		b.WriteString(HelpStyle.Render("Scans in progress... esc: cancel all"))
	} else {
		b.WriteString(HelpStyle.Render("enter: view vulns • r: retry failed • esc: back to repos"))
	}

	return b.String()
}

func (m Model) updateScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Check if scans are still running
	running := false
	for _, item := range m.scanItems {
		if item.Status == ScanStatusRunning {
			running = true
			break
		}
	}

	switch {
	case key.Matches(msg, m.keys.Escape):
		// Clear state and go back
		m.err = nil
		m.scanItems = nil
		m.currentScanIdx = -1
		m.view = ViewRepos
		return m, nil

	case key.Matches(msg, m.keys.Up):
		if m.scanListIndex > 0 {
			m.scanListIndex--
		}

	case key.Matches(msg, m.keys.Down):
		if m.scanListIndex < len(m.scanItems)-1 {
			m.scanListIndex++
		}

	case key.Matches(msg, m.keys.Enter):
		// View vulnerabilities if all scans complete
		if !running && len(m.scanItems) > 0 {
			m.view = ViewVulnsDb
			m.loading = true
			return m, m.loadVulns()
		}

	case key.Matches(msg, m.keys.Refresh):
		// Retry failed scans
		if !running {
			// Find failed scans and reset them to pending
			hasFailedScans := false
			for i, item := range m.scanItems {
				if item.Status == ScanStatusError {
					m.scanItems[i].Status = ScanStatusPending
					m.scanItems[i].Error = ""
					hasFailedScans = true
				}
			}
			if hasFailedScans {
				// Find first pending and start scanning
				for i, item := range m.scanItems {
					if item.Status == ScanStatusPending {
						m.currentScanIdx = i
						m.scanItems[i].Status = ScanStatusRunning
						m.loading = true
						m.statusMsg = fmt.Sprintf("Retrying %s @ %s...", item.Repo.FullName, item.Branch)
						return m, m.runScanWithBranch(item.Repo, item.Branch)
					}
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

// ============================================================================
// VulnsDb View - Vulnerability Database Browser
// ============================================================================

func (m Model) viewVulnsDb() string {
	var b strings.Builder

	// Title
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Vulnerability Database"))
	b.WriteString("\n\n")

	// Sub-tabs for vulnerability types
	vulnTabs := []struct {
		typ   VulnType
		label string
	}{
		{VulnTypeSCA, "SCA (Trivy)"},
		{VulnTypeSAST, "SAST (OpenGrep)"},
		{VulnTypeSecrets, "Secrets (TruffleHog)"},
	}

	var tabsRendered []string
	for i, vt := range vulnTabs {
		style := InactiveTabStyle
		if m.vulnType == vt.typ {
			style = ActiveTabStyle
		}
		if i > 0 {
			tabsRendered = append(tabsRendered, "  ") // Add spacing between tabs
		}
		tabsRendered = append(tabsRendered, style.Render(vt.label))
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabsRendered...))
	b.WriteString("\n\n")

	// Search/filter bar
	if m.vulnSearching {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Render("Search: "))
		b.WriteString(m.vulnSearch)
		b.WriteString("█")
		b.WriteString("\n\n")
	} else if m.vulnSearch != "" {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("Filter: \"%s\" ", m.vulnSearch)))
		b.WriteString(HelpStyle.Render("(press / to search, esc to clear)"))
		b.WriteString("\n\n")
	}

	// Status filter indicator
	if m.vulnStatusFilter != "" {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("Status: %s ", m.vulnStatusFilter)))
		b.WriteString(HelpStyle.Render("(press f to cycle filter)"))
		b.WriteString("\n\n")
	}

	// Loading indicator
	if m.loading {
		b.WriteString(m.spinner.View())
		b.WriteString(" Loading vulnerabilities...")
		return b.String()
	}

	// Render appropriate list based on current tab
	switch m.vulnType {
	case VulnTypeSCA:
		b.WriteString(m.renderSCAList())
	case VulnTypeSAST:
		b.WriteString(m.renderSASTList())
	case VulnTypeSecrets:
		b.WriteString(m.renderSecretsList())
	}

	// Bulk action menu
	if m.vulnShowActions {
		b.WriteString("\n")
		b.WriteString(m.renderBulkActionMenu())
	}

	// Help
	b.WriteString("\n")
	selectedCount := len(m.vulnSelected)
	if selectedCount > 0 {
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("%d selected", selectedCount)))
		b.WriteString(" | ")
	}
	b.WriteString(HelpStyle.Render("tab: switch type | /: search | f: filter status | →: expand | ←: collapse | space: select | a: all | enter: actions"))

	return b.String()
}

func (m Model) renderSCAList() string {
	var b strings.Builder

	items := m.getFilteredSCAItems()
	if len(items) == 0 {
		b.WriteString(SubtleStyle.Render("No SCA vulnerabilities found"))
		return b.String()
	}

	// Header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorMuted)
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-8s %-20s %-10s %-8s %-10s %-25s %-15s %-8s\n",
		"Provider", "Repo", "Branch", "Commit", "Severity", "Package", "CVE", "Status")))
	b.WriteString(strings.Repeat("─", 120) + "\n")

	// Calculate visible range
	visibleStart, visibleEnd := m.calculateVisibleRange(len(items), 15)

	for i := visibleStart; i < visibleEnd; i++ {
		item := items[i]
		isSelected := m.vulnSelected[i]
		isCurrent := i == m.vulnListIndex

		// Selection indicator
		selectIndicator := "  "
		if isSelected {
			selectIndicator = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓ ")
		}

		// Cursor indicator
		cursor := " "
		if isCurrent {
			cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("▸")
		}

		// Severity color
		sevStyle := getSeverityStyle(item.Severity)

		// Check if this row should be expanded (current row + expanded mode)
		if isCurrent && m.vulnRowExpanded {
			// Show full content for expanded row
			b.WriteString(fmt.Sprintf("%s%s\n", cursor, selectIndicator))
			b.WriteString(fmt.Sprintf("    Provider: %s\n", item.Provider))
			b.WriteString(fmt.Sprintf("    Repo:     %s\n", item.Repository))
			b.WriteString(fmt.Sprintf("    Branch:   %s\n", item.Branch))
			b.WriteString(fmt.Sprintf("    Commit:   %s\n", item.Commit))
			b.WriteString(fmt.Sprintf("    Severity: %s\n", sevStyle.Render(item.Severity)))
			b.WriteString(fmt.Sprintf("    Package:  %s\n", item.Package))
			b.WriteString(fmt.Sprintf("    Version:  %s\n", item.Version))
			b.WriteString(fmt.Sprintf("    CVE:      %s\n", item.VulnerabilityID))
			b.WriteString(fmt.Sprintf("    Title:    %s\n", item.Title))
			b.WriteString(fmt.Sprintf("    Status:   %s\n", item.Status))
			if item.JiraTicket != "" {
				b.WriteString(fmt.Sprintf("    Jira:     %s\n", item.JiraTicket))
			}
			b.WriteString(fmt.Sprintf("    First:    %s  Last: %s\n", item.FirstSeen, item.LastSeen))
			b.WriteString("\n")
		} else {
			// Truncate fields for normal view
			provider := truncateString(item.Provider, 6)
			repo := truncateString(item.Repository, 18)
			branch := truncateString(item.Branch, 8)
			commit := truncateString(item.Commit, 6)
			pkg := truncateString(item.Package, 23)
			cve := truncateString(item.VulnerabilityID, 13)

			line := fmt.Sprintf("%s%s%-8s %-20s %-10s %-8s %-10s %-25s %-15s %-8s\n",
				cursor, selectIndicator,
				provider, repo, branch, commit,
				sevStyle.Render(item.Severity),
				pkg, cve, item.Status)

			b.WriteString(line)
		}
	}

	b.WriteString(fmt.Sprintf("\n%d/%d vulnerabilities", len(items), len(m.scaVulns)))

	return b.String()
}

func (m Model) renderSASTList() string {
	var b strings.Builder

	items := m.getFilteredSASTItems()
	if len(items) == 0 {
		b.WriteString(SubtleStyle.Render("No SAST findings found"))
		return b.String()
	}

	// Header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorMuted)
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-8s %-18s %-10s %-8s %-10s %-25s %-20s %-6s %-8s\n",
		"Provider", "Repo", "Branch", "Commit", "Severity", "Rule", "File", "Line", "Status")))
	b.WriteString(strings.Repeat("─", 130) + "\n")

	// Calculate visible range
	visibleStart, visibleEnd := m.calculateVisibleRange(len(items), 15)

	for i := visibleStart; i < visibleEnd; i++ {
		item := items[i]
		isSelected := m.vulnSelected[i]
		isCurrent := i == m.vulnListIndex

		selectIndicator := "  "
		if isSelected {
			selectIndicator = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓ ")
		}

		cursor := " "
		if isCurrent {
			cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("▸")
		}

		sevStyle := getSeverityStyle(item.Severity)

		// Check if this row should be expanded (current row + expanded mode)
		if isCurrent && m.vulnRowExpanded {
			// Show full content for expanded row
			b.WriteString(fmt.Sprintf("%s%s\n", cursor, selectIndicator))
			b.WriteString(fmt.Sprintf("    Provider: %s\n", item.Provider))
			b.WriteString(fmt.Sprintf("    Repo:     %s\n", item.Repository))
			b.WriteString(fmt.Sprintf("    Branch:   %s\n", item.Branch))
			b.WriteString(fmt.Sprintf("    Commit:   %s\n", item.Commit))
			b.WriteString(fmt.Sprintf("    Severity: %s\n", sevStyle.Render(item.Severity)))
			b.WriteString(fmt.Sprintf("    Scanner:  %s\n", item.Scanner))
			b.WriteString(fmt.Sprintf("    Rule:     %s\n", item.CheckID))
			b.WriteString(fmt.Sprintf("    File:     %s\n", item.FilePath))
			b.WriteString(fmt.Sprintf("    Line:     %d\n", item.Line))
			b.WriteString(fmt.Sprintf("    Message:  %s\n", item.Message))
			b.WriteString(fmt.Sprintf("    Status:   %s\n", item.Status))
			if item.JiraTicket != "" {
				b.WriteString(fmt.Sprintf("    Jira:     %s\n", item.JiraTicket))
			}
			b.WriteString(fmt.Sprintf("    First:    %s  Last: %s\n", item.FirstSeen, item.LastSeen))
			b.WriteString("\n")
		} else {
			// Truncate fields for normal view
			provider := truncateString(item.Provider, 6)
			repo := truncateString(item.Repository, 16)
			branch := truncateString(item.Branch, 8)
			commit := truncateString(item.Commit, 6)
			rule := truncateString(item.CheckID, 23)
			file := truncateString(item.FilePath, 18)

			line := fmt.Sprintf("%s%s%-8s %-18s %-10s %-8s %-10s %-25s %-20s %-6d %-8s\n",
				cursor, selectIndicator,
				provider, repo, branch, commit,
				sevStyle.Render(item.Severity),
				rule, file, item.Line, item.Status)

			b.WriteString(line)
		}
	}

	b.WriteString(fmt.Sprintf("\n%d/%d findings", len(items), len(m.sastVulns)))

	return b.String()
}

func (m Model) renderSecretsList() string {
	var b strings.Builder

	items := m.getFilteredSecretsItems()
	if len(items) == 0 {
		b.WriteString(SubtleStyle.Render("No secrets findings found"))
		return b.String()
	}

	// Header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorMuted)
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-8s %-18s %-10s %-8s %-10s %-18s %-25s %-6s %-8s\n",
		"Provider", "Repo", "Branch", "Commit", "Verified", "Detector", "File", "Line", "Status")))
	b.WriteString(strings.Repeat("─", 130) + "\n")

	// Calculate visible range
	visibleStart, visibleEnd := m.calculateVisibleRange(len(items), 15)

	for i := visibleStart; i < visibleEnd; i++ {
		item := items[i]
		isSelected := m.vulnSelected[i]
		isCurrent := i == m.vulnListIndex

		selectIndicator := "  "
		if isSelected {
			selectIndicator = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓ ")
		}

		cursor := " "
		if isCurrent {
			cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("▸")
		}

		verified := SubtleStyle.Render("No")
		verifiedLabel := "No"
		if item.Verified {
			verified = ErrorStyle.Render("YES")
			verifiedLabel = "YES (ACTIVE SECRET!)"
		}

		// Check if this row should be expanded (current row + expanded mode)
		if isCurrent && m.vulnRowExpanded {
			// Show full content for expanded row
			b.WriteString(fmt.Sprintf("%s%s\n", cursor, selectIndicator))
			b.WriteString(fmt.Sprintf("    Provider: %s\n", item.Provider))
			b.WriteString(fmt.Sprintf("    Repo:     %s\n", item.Repository))
			b.WriteString(fmt.Sprintf("    Branch:   %s\n", item.Branch))
			b.WriteString(fmt.Sprintf("    Commit:   %s\n", item.Commit))
			b.WriteString(fmt.Sprintf("    Verified: %s\n", verifiedLabel))
			b.WriteString(fmt.Sprintf("    Detector: %s\n", item.DetectorName))
			b.WriteString(fmt.Sprintf("    File:     %s\n", item.FilePath))
			b.WriteString(fmt.Sprintf("    Line:     %d\n", item.Line))
			b.WriteString(fmt.Sprintf("    Severity: %s\n", item.Severity))
			b.WriteString(fmt.Sprintf("    Status:   %s\n", item.Status))
			if item.JiraTicket != "" {
				b.WriteString(fmt.Sprintf("    Jira:     %s\n", item.JiraTicket))
			}
			b.WriteString(fmt.Sprintf("    First:    %s  Last: %s\n", item.FirstSeen, item.LastSeen))
			b.WriteString("\n")
		} else {
			// Truncate fields for normal view
			provider := truncateString(item.Provider, 6)
			repo := truncateString(item.Repository, 16)
			branch := truncateString(item.Branch, 8)
			commit := truncateString(item.Commit, 6)
			detector := truncateString(item.DetectorName, 16)
			file := truncateString(item.FilePath, 23)

			line := fmt.Sprintf("%s%s%-8s %-18s %-10s %-8s %-10s %-18s %-25s %-6d %-8s\n",
				cursor, selectIndicator,
				provider, repo, branch, commit,
				verified, detector, file, item.Line, item.Status)

			b.WriteString(line)
		}
	}

	b.WriteString(fmt.Sprintf("\n%d/%d secrets", len(items), len(m.secretsVulns)))

	return b.String()
}

func (m Model) renderBulkActionMenu() string {
	var b strings.Builder

	menuStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(0, 1)

	actions := []struct {
		key  string
		name string
	}{
		{"i", "Mark as Ignored"},
		{"o", "Mark as Open"},
		{"t", "Create JIRA Ticket (coming soon)"},
		{"esc", "Cancel"},
	}

	b.WriteString("Bulk Actions:\n")
	for _, a := range actions {
		keyStyle := lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true)
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render("["+a.key+"]"), a.name))
	}

	return menuStyle.Render(b.String())
}

func (m Model) calculateVisibleRange(total, pageSize int) (int, int) {
	if total == 0 {
		return 0, 0
	}

	// Center the current selection
	start := m.vulnListIndex - pageSize/2
	if start < 0 {
		start = 0
	}

	end := start + pageSize
	if end > total {
		end = total
		start = end - pageSize
		if start < 0 {
			start = 0
		}
	}

	return start, end
}

func (m Model) getFilteredSCAItems() []SCAVulnItem {
	var filtered []SCAVulnItem
	for _, item := range m.scaVulns {
		if m.vulnStatusFilter != "" && item.Status != m.vulnStatusFilter {
			continue
		}
		if m.vulnSearch != "" {
			search := strings.ToLower(m.vulnSearch)
			if !strings.Contains(strings.ToLower(item.Package), search) &&
				!strings.Contains(strings.ToLower(item.VulnerabilityID), search) &&
				!strings.Contains(strings.ToLower(item.Repository), search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func (m Model) getFilteredSASTItems() []SASTVulnItem {
	var filtered []SASTVulnItem
	for _, item := range m.sastVulns {
		if m.vulnStatusFilter != "" && item.Status != m.vulnStatusFilter {
			continue
		}
		if m.vulnSearch != "" {
			search := strings.ToLower(m.vulnSearch)
			if !strings.Contains(strings.ToLower(item.CheckID), search) &&
				!strings.Contains(strings.ToLower(item.FilePath), search) &&
				!strings.Contains(strings.ToLower(item.Repository), search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func (m Model) getFilteredSecretsItems() []SecretsVulnItem {
	var filtered []SecretsVulnItem
	for _, item := range m.secretsVulns {
		if m.vulnStatusFilter != "" && item.Status != m.vulnStatusFilter {
			continue
		}
		if m.vulnSearch != "" {
			search := strings.ToLower(m.vulnSearch)
			if !strings.Contains(strings.ToLower(item.DetectorName), search) &&
				!strings.Contains(strings.ToLower(item.FilePath), search) &&
				!strings.Contains(strings.ToLower(item.Repository), search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func getSeverityStyle(severity string) lipgloss.Style {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Bright red
	case "HIGH", "ERROR":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("202")) // Orange-red
	case "MEDIUM", "WARNING":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // Orange
	case "LOW", "INFO":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("226")) // Yellow
	default:
		return SubtleStyle
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (m Model) updateVulnsDb(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle search input mode
	if m.vulnSearching {
		switch msg.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.vulnSearching = false
			m.vulnListIndex = 0
			m.vulnSelected = make(map[int]bool)
		case tea.KeyBackspace:
			if len(m.vulnSearch) > 0 {
				m.vulnSearch = m.vulnSearch[:len(m.vulnSearch)-1]
			}
		case tea.KeyRunes:
			m.vulnSearch += string(msg.Runes)
		}
		return m, nil
	}

	// Handle bulk action menu
	if m.vulnShowActions {
		switch msg.String() {
		case "esc":
			m.vulnShowActions = false
		case "i":
			m.markSelectedVulns("ignored")
			m.vulnShowActions = false
		case "o":
			m.markSelectedVulns("open")
			m.vulnShowActions = false
		case "t":
			m.statusMsg = "JIRA ticket creation coming soon!"
			m.vulnShowActions = false
		}
		return m, nil
	}

	// Get current list length
	listLen := m.getCurrentVulnListLen()

	switch {
	// Navigation
	case key.Matches(msg, m.keys.Up):
		if m.vulnListIndex > 0 {
			m.vulnListIndex--
			m.vulnRowExpanded = false // Collapse when navigating
		}
	case key.Matches(msg, m.keys.Down):
		if m.vulnListIndex < listLen-1 {
			m.vulnListIndex++
			m.vulnRowExpanded = false // Collapse when navigating
		}
	case key.Matches(msg, m.keys.PageUp):
		m.vulnListIndex -= 10
		if m.vulnListIndex < 0 {
			m.vulnListIndex = 0
		}
		m.vulnRowExpanded = false // Collapse when navigating
	case key.Matches(msg, m.keys.PageDown):
		m.vulnListIndex += 10
		if m.vulnListIndex >= listLen {
			m.vulnListIndex = listLen - 1
		}
		if m.vulnListIndex < 0 {
			m.vulnListIndex = 0
		}
		m.vulnRowExpanded = false // Collapse when navigating

	// Row expansion (Right to expand, Left to collapse)
	case key.Matches(msg, m.keys.Right):
		m.vulnRowExpanded = true
	case key.Matches(msg, m.keys.Left):
		m.vulnRowExpanded = false

	// Tab switching
	case key.Matches(msg, m.keys.Tab):
		m.vulnType = (m.vulnType + 1) % 3
		m.vulnListIndex = 0
		m.vulnSelected = make(map[int]bool)
		m.loading = true
		return m, m.loadVulns()
	case key.Matches(msg, m.keys.ShiftTab):
		m.vulnType = (m.vulnType + 2) % 3 // Go backwards
		m.vulnListIndex = 0
		m.vulnSelected = make(map[int]bool)
		m.loading = true
		return m, m.loadVulns()

	// Search
	case key.Matches(msg, m.keys.Search):
		m.vulnSearching = true
		m.vulnSearch = ""

	// Status filter
	case msg.String() == "f":
		// Cycle through status filters: "" -> "open" -> "fixed" -> "ignored" -> ""
		switch m.vulnStatusFilter {
		case "":
			m.vulnStatusFilter = "open"
		case "open":
			m.vulnStatusFilter = "fixed"
		case "fixed":
			m.vulnStatusFilter = "ignored"
		default:
			m.vulnStatusFilter = ""
		}
		m.vulnListIndex = 0

	// Sort
	case msg.String() == "s":
		m.vulnSortField = (m.vulnSortField + 1) % 4
		m.statusMsg = fmt.Sprintf("Sorting by: %s", m.vulnSortField.String())

	// Selection
	case key.Matches(msg, m.keys.Space):
		if listLen > 0 {
			m.vulnSelected[m.vulnListIndex] = !m.vulnSelected[m.vulnListIndex]
			if !m.vulnSelected[m.vulnListIndex] {
				delete(m.vulnSelected, m.vulnListIndex)
			}
		}

	case key.Matches(msg, m.keys.SelectAll):
		for i := 0; i < listLen; i++ {
			m.vulnSelected[i] = true
		}

	case key.Matches(msg, m.keys.SelectNone):
		m.vulnSelected = make(map[int]bool)

	// Bulk actions
	case key.Matches(msg, m.keys.Enter):
		if len(m.vulnSelected) > 0 {
			m.vulnShowActions = true
		}

	// Refresh
	case key.Matches(msg, m.keys.Refresh):
		m.loading = true
		return m, m.loadVulns()

	// Clear search on escape
	case key.Matches(msg, m.keys.Escape):
		if m.vulnSearch != "" {
			m.vulnSearch = ""
			m.vulnListIndex = 0
		}
	}

	return m, nil
}

func (m Model) getCurrentVulnListLen() int {
	switch m.vulnType {
	case VulnTypeSCA:
		return len(m.getFilteredSCAItems())
	case VulnTypeSAST:
		return len(m.getFilteredSASTItems())
	case VulnTypeSecrets:
		return len(m.getFilteredSecretsItems())
	}
	return 0
}

func (m *Model) markSelectedVulns(status string) {
	if m.db == nil {
		return
	}
	ctx := context.Background()

	switch m.vulnType {
	case VulnTypeSCA:
		items := m.getFilteredSCAItems()
		for idx := range m.vulnSelected {
			if idx < len(items) {
				_ = m.db.UpdateSCAFindingStatus(ctx, items[idx].PrimaryKey, status, "")
			}
		}
	case VulnTypeSAST:
		items := m.getFilteredSASTItems()
		for idx := range m.vulnSelected {
			if idx < len(items) {
				_ = m.db.UpdateSASTFindingStatus(ctx, items[idx].PrimaryKey, status, "")
			}
		}
	case VulnTypeSecrets:
		items := m.getFilteredSecretsItems()
		for idx := range m.vulnSelected {
			if idx < len(items) {
				_ = m.db.UpdateSecretsFindingStatus(ctx, items[idx].PrimaryKey, status, "")
			}
		}
	}

	m.vulnSelected = make(map[int]bool)
	m.statusMsg = fmt.Sprintf("Marked %d items as %s", len(m.vulnSelected), status)
}

// ============================================================================
// Licenses View - License Findings Browser
// ============================================================================

func (m Model) viewLicenses() string {
	var b strings.Builder

	// Title
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("License Findings"))
	b.WriteString("\n\n")

	// Search/filter bar
	if m.licenseSearching {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorPrimary).Render("Search: "))
		b.WriteString(m.licenseSearch)
		b.WriteString("█")
		b.WriteString("\n\n")
	} else if m.licenseSearch != "" {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("Filter: \"%s\" ", m.licenseSearch)))
		b.WriteString(HelpStyle.Render("(press / to search, esc to clear)"))
		b.WriteString("\n\n")
	}

	// Status filter indicator
	if m.licenseStatusFilter != "" {
		b.WriteString(SubtleStyle.Render(fmt.Sprintf("Status: %s ", m.licenseStatusFilter)))
		b.WriteString(HelpStyle.Render("(press f to cycle filter)"))
		b.WriteString("\n\n")
	}

	// Loading indicator
	if m.loading {
		b.WriteString(m.spinner.View())
		b.WriteString(" Loading license findings...")
		return b.String()
	}

	// Render license list
	b.WriteString(m.renderLicenseList())

	// Bulk action menu
	if m.licenseShowActions {
		b.WriteString("\n")
		b.WriteString(m.renderLicenseBulkActionMenu())
	}

	// Help
	b.WriteString("\n")
	selectedCount := len(m.licenseSelected)
	if selectedCount > 0 {
		b.WriteString(SuccessStyle.Render(fmt.Sprintf("%d selected", selectedCount)))
		b.WriteString(" | ")
	}
	b.WriteString(HelpStyle.Render("/: search | f: filter status | →: expand | ←: collapse | space: select | a: all | n: none | enter: actions"))

	return b.String()
}

func (m Model) renderLicenseList() string {
	var b strings.Builder

	items := m.getFilteredLicenseItems()
	if len(items) == 0 {
		b.WriteString(SubtleStyle.Render("No license findings found"))
		return b.String()
	}

	// Header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorMuted)
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-8s %-18s %-10s %-8s %-10s %-12s %-22s %-12s %-8s\n",
		"Provider", "Repo", "Branch", "Commit", "Severity", "Class", "Package", "License", "Status")))
	b.WriteString(strings.Repeat("─", 130) + "\n")

	// Calculate visible range
	visibleStart, visibleEnd := m.calculateLicenseVisibleRange(len(items), 15)

	for i := visibleStart; i < visibleEnd; i++ {
		item := items[i]
		isSelected := m.licenseSelected[i]
		isCurrent := i == m.licenseListIndex

		// Selection indicator
		selectIndicator := "  "
		if isSelected {
			selectIndicator = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓ ")
		}

		// Cursor indicator
		cursor := " "
		if isCurrent {
			cursor = lipgloss.NewStyle().Foreground(ColorPrimary).Render("▸")
		}

		// Severity and classification styling
		sevStyle := getSeverityStyle(item.Severity)
		classStyle := getClassificationStyle(item.Classification)

		// Check if this row should be expanded (current row + expanded mode)
		if isCurrent && m.licenseRowExpanded {
			// Show full content for expanded row
			b.WriteString(fmt.Sprintf("%s%s\n", cursor, selectIndicator))
			b.WriteString(fmt.Sprintf("    Provider:       %s\n", item.Provider))
			b.WriteString(fmt.Sprintf("    Repo:           %s\n", item.Repository))
			b.WriteString(fmt.Sprintf("    Branch:         %s\n", item.Branch))
			b.WriteString(fmt.Sprintf("    Commit:         %s\n", item.Commit))
			b.WriteString(fmt.Sprintf("    Severity:       %s\n", sevStyle.Render(item.Severity)))
			b.WriteString(fmt.Sprintf("    Classification: %s\n", classStyle.Render(item.Classification)))
			b.WriteString(fmt.Sprintf("    Package:        %s\n", item.Package))
			b.WriteString(fmt.Sprintf("    Version:        %s\n", item.Version))
			b.WriteString(fmt.Sprintf("    License:        %s\n", item.License))
			b.WriteString(fmt.Sprintf("    Pkg Path:       %s\n", item.PkgPath))
			b.WriteString(fmt.Sprintf("    Pkg Type:       %s\n", item.PkgType))
			b.WriteString(fmt.Sprintf("    Status:         %s\n", item.Status))
			if item.JiraTicket != "" {
				b.WriteString(fmt.Sprintf("    Jira:           %s\n", item.JiraTicket))
			}
			b.WriteString(fmt.Sprintf("    First:          %s  Last: %s\n", item.FirstSeen, item.LastSeen))
			b.WriteString("\n")
		} else {
			// Truncate fields for normal view
			provider := truncateString(item.Provider, 6)
			repo := truncateString(item.Repository, 16)
			branch := truncateString(item.Branch, 8)
			commit := truncateString(item.Commit, 6)
			pkg := truncateString(item.Package+"@"+item.Version, 20)
			license := truncateString(item.License, 10)
			class := truncateString(item.Classification, 10)

			line := fmt.Sprintf("%s%s%-8s %-18s %-10s %-8s %-10s %-12s %-22s %-12s %-8s\n",
				cursor, selectIndicator,
				provider, repo, branch, commit,
				sevStyle.Render(item.Severity),
				classStyle.Render(class),
				pkg, license, item.Status)

			b.WriteString(line)
		}
	}

	b.WriteString(fmt.Sprintf("\n%d/%d license findings", len(items), len(m.licenseVulns)))

	return b.String()
}

func (m Model) renderLicenseBulkActionMenu() string {
	var b strings.Builder

	menuStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Padding(0, 1)

	actions := []struct {
		key  string
		name string
	}{
		{"i", "Mark as Ignored"},
		{"o", "Mark as Open"},
		{"t", "Create JIRA Ticket (coming soon)"},
		{"esc", "Cancel"},
	}

	b.WriteString("Bulk Actions:\n")
	for _, a := range actions {
		keyStyle := lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true)
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render("["+a.key+"]"), a.name))
	}

	return menuStyle.Render(b.String())
}

func (m Model) calculateLicenseVisibleRange(total, pageSize int) (int, int) {
	if total == 0 {
		return 0, 0
	}

	// Center the current selection
	start := m.licenseListIndex - pageSize/2
	if start < 0 {
		start = 0
	}

	end := start + pageSize
	if end > total {
		end = total
		start = end - pageSize
		if start < 0 {
			start = 0
		}
	}

	return start, end
}

func (m Model) getFilteredLicenseItems() []LicenseVulnItem {
	var filtered []LicenseVulnItem
	for _, item := range m.licenseVulns {
		if m.licenseStatusFilter != "" && item.Status != m.licenseStatusFilter {
			continue
		}
		if m.licenseSearch != "" {
			search := strings.ToLower(m.licenseSearch)
			if !strings.Contains(strings.ToLower(item.Package), search) &&
				!strings.Contains(strings.ToLower(item.License), search) &&
				!strings.Contains(strings.ToLower(item.Repository), search) &&
				!strings.Contains(strings.ToLower(item.Classification), search) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func getClassificationStyle(classification string) lipgloss.Style {
	switch strings.ToLower(classification) {
	case "restricted":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Red
	case "reciprocal":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // Orange
	case "permissive":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("40")) // Green
	default:
		return SubtleStyle
	}
}

func (m Model) updateLicenses(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle search input mode
	if m.licenseSearching {
		switch msg.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.licenseSearching = false
			m.licenseListIndex = 0
			m.licenseSelected = make(map[int]bool)
		case tea.KeyBackspace:
			if len(m.licenseSearch) > 0 {
				m.licenseSearch = m.licenseSearch[:len(m.licenseSearch)-1]
			}
		case tea.KeyRunes:
			m.licenseSearch += string(msg.Runes)
		}
		return m, nil
	}

	// Handle bulk action menu
	if m.licenseShowActions {
		switch msg.String() {
		case "esc":
			m.licenseShowActions = false
		case "i":
			m.markSelectedLicenses("ignored")
			m.licenseShowActions = false
		case "o":
			m.markSelectedLicenses("open")
			m.licenseShowActions = false
		case "t":
			m.statusMsg = "JIRA ticket creation coming soon!"
			m.licenseShowActions = false
		}
		return m, nil
	}

	// Get current list length
	listLen := len(m.getFilteredLicenseItems())

	switch {
	// Navigation
	case key.Matches(msg, m.keys.Up):
		if m.licenseListIndex > 0 {
			m.licenseListIndex--
			m.licenseRowExpanded = false // Collapse when navigating
		}
	case key.Matches(msg, m.keys.Down):
		if m.licenseListIndex < listLen-1 {
			m.licenseListIndex++
			m.licenseRowExpanded = false // Collapse when navigating
		}
	case key.Matches(msg, m.keys.PageUp):
		m.licenseListIndex -= 10
		if m.licenseListIndex < 0 {
			m.licenseListIndex = 0
		}
		m.licenseRowExpanded = false // Collapse when navigating
	case key.Matches(msg, m.keys.PageDown):
		m.licenseListIndex += 10
		if m.licenseListIndex >= listLen {
			m.licenseListIndex = listLen - 1
		}
		if m.licenseListIndex < 0 {
			m.licenseListIndex = 0
		}
		m.licenseRowExpanded = false // Collapse when navigating

	// Row expansion (Right to expand, Left to collapse)
	case key.Matches(msg, m.keys.Right):
		m.licenseRowExpanded = true
	case key.Matches(msg, m.keys.Left):
		m.licenseRowExpanded = false

	// Search
	case key.Matches(msg, m.keys.Search):
		m.licenseSearching = true
		m.licenseSearch = ""

	// Status filter
	case msg.String() == "f":
		// Cycle through status filters: "" -> "open" -> "ignored" -> ""
		switch m.licenseStatusFilter {
		case "":
			m.licenseStatusFilter = "open"
		case "open":
			m.licenseStatusFilter = "ignored"
		default:
			m.licenseStatusFilter = ""
		}
		m.licenseListIndex = 0

	// Selection
	case key.Matches(msg, m.keys.Space):
		if listLen > 0 {
			m.licenseSelected[m.licenseListIndex] = !m.licenseSelected[m.licenseListIndex]
			if !m.licenseSelected[m.licenseListIndex] {
				delete(m.licenseSelected, m.licenseListIndex)
			}
		}

	case key.Matches(msg, m.keys.SelectAll):
		for i := 0; i < listLen; i++ {
			m.licenseSelected[i] = true
		}

	case key.Matches(msg, m.keys.SelectNone):
		m.licenseSelected = make(map[int]bool)

	// Bulk actions
	case key.Matches(msg, m.keys.Enter):
		if len(m.licenseSelected) > 0 {
			m.licenseShowActions = true
		}

	// Refresh
	case key.Matches(msg, m.keys.Refresh):
		m.loading = true
		return m, m.loadLicenses()

	// Clear search on escape
	case key.Matches(msg, m.keys.Escape):
		if m.licenseSearch != "" {
			m.licenseSearch = ""
			m.licenseListIndex = 0
		}
	}

	return m, nil
}

func (m *Model) markSelectedLicenses(status string) {
	if m.db == nil {
		return
	}
	ctx := context.Background()

	items := m.getFilteredLicenseItems()
	count := 0
	for idx := range m.licenseSelected {
		if idx < len(items) {
			_ = m.db.UpdateLicenseFindingStatus(ctx, items[idx].PrimaryKey, status, "")
			count++
		}
	}

	m.licenseSelected = make(map[int]bool)
	m.statusMsg = fmt.Sprintf("Marked %d license items as %s", count, status)
}
