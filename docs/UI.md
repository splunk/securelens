# SecureLens TUI Development Guide

This document provides comprehensive information for developing and extending the SecureLens Terminal User Interface (TUI). It's designed to help LLMs and developers quickly understand the architecture and add new features.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Libraries & Dependencies](#libraries--dependencies)
3. [File Structure](#file-structure)
4. [Core Components](#core-components)
5. [State Management](#state-management)
6. [Key Bindings](#key-bindings)
7. [Views](#views)
8. [Adding New Features](#adding-new-features)
9. [Common Patterns](#common-patterns)
10. [Integration Points](#integration-points)

---

## Architecture Overview

The TUI follows the **Elm Architecture** (Model-Update-View) via the Bubble Tea framework:

```
┌─────────────────────────────────────────────────────────────┐
│                        User Input                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      tea.Msg                                │
│  (KeyMsg, WindowSizeMsg, custom messages)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Model.Update()                            │
│  - Process message                                          │
│  - Update state                                             │
│  - Return new model + optional tea.Cmd                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Model.View()                             │
│  - Render current state to string                           │
│  - Uses lipgloss for styling                                │
└─────────────────────────────────────────────────────────────┘
```

---

## Libraries & Dependencies

### Bubble Tea (github.com/charmbracelet/bubbletea)
The core TUI framework. Key concepts:
- `tea.Model` - Interface with `Init()`, `Update()`, `View()` methods
- `tea.Cmd` - Asynchronous commands that return `tea.Msg`
- `tea.Msg` - Messages that trigger state updates
- `tea.Program` - The main program runner

**Reference**: https://github.com/charmbracelet/bubbletea

### Bubbles (github.com/charmbracelet/bubbles)
Pre-built components:
- `spinner.Model` - Loading spinners
- `help.Model` - Help text display
- `key.Binding` - Key binding definitions
- `list.Model` - Filterable lists (not currently used, could replace manual list)
- `table.Model` - Tables (could enhance results view)
- `textinput.Model` - Text inputs (could replace manual input handling)
- `viewport.Model` - Scrollable content

**Reference**: https://github.com/charmbracelet/bubbles

### Lipgloss (github.com/charmbracelet/lipgloss)
Styling library:
- `lipgloss.Style` - Define styles (colors, borders, padding)
- `lipgloss.JoinHorizontal/Vertical` - Layout composition
- `lipgloss.NewStyle()` - Create new style

**Reference**: https://github.com/charmbracelet/lipgloss

---

## File Structure

```
cli/ui/
├── cmd.go          # Cobra command definition for "securelens ui"
├── app.go          # Program initialization (tea.NewProgram)
├── model.go        # Main Model struct and Update() logic
├── views.go        # View rendering functions for each screen
├── styles.go       # Lipgloss style definitions
├── keys.go         # Key binding definitions (KeyMap)
├── messages.go     # Custom tea.Msg types
```

### Key Files

#### `model.go`
Contains the main `Model` struct with all application state:
```go
type Model struct {
    // Current view
    view ViewType  // ViewHome, ViewRepos, ViewScan, ViewResults, ViewWizard

    // Configuration
    config   *config.Config
    scanMode string  // "standalone" or "remote"

    // Data
    repos       []scan.DiscoveredRepository
    manualRepos []scan.DiscoveredRepository  // Persist across reloads
    selected    map[int]bool
    reports     []*scan.ScanReport

    // UI state
    loading       bool
    err           error
    statusMsg     string
    showHelp      bool
    searching     bool
    addingRepoURL bool
    searchFilter  string
    repoURLInput  string

    // Pagination
    repoPageSize   int
    hasMoreRepos   bool
    repoLoadCount  int
    loadedProvider string

    // Components
    keys    KeyMap
    help    help.Model
    spinner spinner.Model
    width   int
    height  int
}
```

#### `views.go`
Contains view rendering and view-specific update handlers:
- `viewHome()` - Home/dashboard view
- `viewRepos()` - Repository browser with filtering
- `viewScan()` - Scan progress view
- `viewResults()` - Results display
- `viewWizard()` - Provider setup wizard
- `updateRepos(msg)` - Handle repo view key events
- `filterReposByTab()` - Filter repos by provider tab

#### `messages.go`
Custom message types:
```go
type ReposLoadedMsg struct {
    Repos    []scan.DiscoveredRepository
    Limit    int
    Provider string
}

type ScanStartMsg struct {
    Repos []scan.DiscoveredRepository
}

type ScanCompleteMsg struct {
    Report *scan.ScanReport
    Error  error
}

type ErrorMsg struct {
    Err error
}

type StatusMsg string
```

---

## State Management

### Input Modes
The app has special input modes that capture all keystrokes:
- `m.searching` - Search filter input mode
- `m.addingRepoURL` - URL input mode

**IMPORTANT**: Input modes must be checked BEFORE global key handling to prevent keys like `q` from quitting:
```go
case tea.KeyMsg:
    // Handle input modes FIRST
    if m.searching || m.addingRepoURL {
        return m.updateRepos(msg)
    }
    // Then global keys...
```

### View Types
```go
type ViewType int
const (
    ViewHome ViewType = iota
    ViewRepos
    ViewScan
    ViewResults
    ViewWizard
)
```

### Provider Tab Filtering
Tab indices map to providers:
- 0 = All
- 1 = GitHub
- 2 = GitLab
- 3 = Bitbucket

When switching tabs, repos are reloaded from the API filtered by provider.

---

## Key Bindings

Defined in `keys.go`:

| Key | Action | Context |
|-----|--------|---------|
| `q` | Quit/Back | Global (not in input mode) |
| `?` | Toggle help | Global |
| `1` | Go to Home | Global |
| `2` | Go to Repos | Global |
| `3` | Go to Results | Global |
| `/` | Enter search mode | Repos view |
| `+` or `u` | Add repo URL | Repos view |
| `space` | Toggle selection | Repos view |
| `enter` | Confirm/Scan | Repos view |
| `tab` | Next provider tab | Repos view |
| `shift+tab` | Previous provider tab | Repos view |
| `r` | Refresh | Repos view |
| `m` | Load more repos | Repos view |
| `esc` | Cancel/Clear | Input modes |
| `↑/k` | Up | Navigation |
| `↓/j` | Down | Navigation |

---

## Views

### Home View (`viewHome`)
Dashboard with quick actions and status summary.

### Repos View (`viewRepos`)
Repository browser with:
- Provider tabs (All/GitHub/GitLab/Bitbucket)
- Search/filter bar
- Add URL input bar
- Scrollable repo list with selection indicators
- Pagination with "load more"

**Key features**:
- Manual repos persist across reloads via `manualRepos` slice
- Scroll indicators show items above/below viewport
- Provider badge, visibility, and source tags per repo

### Scan View (`viewScan`)
Shows scanning progress with:
- Spinner animation
- Per-scanner status indicators
- Error display with retry option

### Results View (`viewResults`)
Displays scan results with:
- Repository info header
- Scanner summary table
- Severity breakdown

---

## Adding New Features

### Adding a New Key Binding

1. Add to `KeyMap` struct in `keys.go`:
```go
type KeyMap struct {
    // ...existing...
    NewAction key.Binding
}
```

2. Define the binding in `DefaultKeyMap()`:
```go
NewAction: key.NewBinding(
    key.WithKeys("x"),
    key.WithHelp("x", "new action"),
),
```

3. Handle in the appropriate view's update function:
```go
case key.Matches(msg, m.keys.NewAction):
    // Handle action
    return m, nil
```

### Adding a New View

1. Add view type in `messages.go`:
```go
const (
    // ...existing...
    ViewNewFeature
)
```

2. Add view function in `views.go`:
```go
func (m Model) viewNewFeature() string {
    var b strings.Builder
    // Render view
    return b.String()
}
```

3. Add update handler in `views.go`:
```go
func (m Model) updateNewFeature(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
    // Handle keys
    return m, nil
}
```

4. Add to `View()` switch in `model.go`:
```go
case ViewNewFeature:
    content = m.viewNewFeature()
```

5. Add to `Update()` switch in `model.go`:
```go
case ViewNewFeature:
    return m.updateNewFeature(msg)
```

### Adding a New Async Operation

1. Define message types in `messages.go`:
```go
type MyOperationStartMsg struct {
    Param string
}
type MyOperationCompleteMsg struct {
    Result string
    Error  error
}
```

2. Create command function in `model.go`:
```go
func (m Model) runMyOperation(param string) tea.Cmd {
    return func() tea.Msg {
        // Do async work
        result, err := someOperation(param)
        return MyOperationCompleteMsg{Result: result, Error: err}
    }
}
```

3. Handle in `Update()`:
```go
case MyOperationStartMsg:
    m.loading = true
    return m, m.runMyOperation(msg.Param)
case MyOperationCompleteMsg:
    m.loading = false
    if msg.Error != nil {
        m.err = msg.Error
    } else {
        // Process result
    }
```

### Adding Input Mode

1. Add state fields to `Model`:
```go
inputMode     bool
inputBuffer   string
```

2. Check input mode FIRST in `Update()`:
```go
if m.inputMode {
    return m.updateInputMode(msg)
}
```

3. Handle input in update function:
```go
func (m Model) updateInputMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
    switch msg.Type {
    case tea.KeyEsc:
        m.inputMode = false
        m.inputBuffer = ""
    case tea.KeyEnter:
        // Process input
        m.inputMode = false
    case tea.KeyBackspace:
        if len(m.inputBuffer) > 0 {
            m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
        }
    default:
        if msg.Type == tea.KeyRunes {
            m.inputBuffer += string(msg.Runes)
        }
    }
    return m, nil
}
```

---

## Common Patterns

### Rendering with StringBuilder
```go
func (m Model) viewSomething() string {
    var b strings.Builder
    b.WriteString(lipgloss.NewStyle().Bold(true).Render("Title"))
    b.WriteString("\n\n")
    // More content...
    return b.String()
}
```

### Conditional Styling
```go
style := InactiveTabStyle
if isActive {
    style = ActiveTabStyle
}
b.WriteString(style.Render("Tab Name"))
```

### List with Scrolling
```go
pageSize := 20
startIdx := 0
if m.listIndex >= pageSize {
    startIdx = m.listIndex - pageSize + 1
}
endIdx := min(startIdx + pageSize, len(items))

for i := startIdx; i < endIdx; i++ {
    prefix := "  "
    if i == m.listIndex {
        prefix = "> "
    }
    // Render item
}
```

### Loading States
```go
if m.loading {
    b.WriteString(m.spinner.View() + " Loading...")
    return b.String()
}
```

---

## Integration Points

### Scan Package (`cli/scan`)
- `scan.DiscoverRepositories()` - Discover repos from configured providers
- `scan.ScanRepository()` - Run security scan on a repo
- `scan.FilterConfigByProvider()` - Filter config for specific provider
- `scan.DiscoveredRepository` - Repository data structure
- `scan.ScanReport` - Scan results structure

### Config Package (`internal/config`)
- `config.Load()` - Load configuration from file
- `config.Config` - Configuration structure with Git providers

### Provider Libraries (`lib/github`, `lib/gitlab`, `lib/bitbucket`)
- API clients for each provider
- Support for organizations, groups, workspaces
- Pagination handling

---

## Style Reference

Defined in `styles.go`:

```go
// Colors
ColorPrimary    = lipgloss.Color("86")   // Cyan
ColorSecondary  = lipgloss.Color("99")   // Purple
ColorSuccess    = lipgloss.Color("78")   // Green
ColorWarning    = lipgloss.Color("214")  // Orange
ColorError      = lipgloss.Color("196")  // Red
ColorMuted      = lipgloss.Color("241")  // Gray
ColorBorder     = lipgloss.Color("238")  // Dark gray

// Styles
TitleStyle        // Bold, primary color background
ActiveTabStyle    // Primary border
InactiveTabStyle  // Muted border
SelectedStyle     // Bold
SubtleStyle       // Muted color
ErrorStyle        // Error color
SuccessStyle      // Success color
HelpStyle         // Muted, small
```

---

## Debugging Tips

1. **Status messages**: Use `m.statusMsg = "debug info"` to display temporary info
2. **Error display**: Set `m.err = fmt.Errorf("error message")` to show errors
3. **Logging**: Use `slog.Info()` - output appears in terminal after TUI exits
4. **Build**: `CGO_ENABLED=1 go build -o securelens ./cmd/securelens`

---

## Future Enhancements

Potential improvements:
1. **API Search**: Add GitHub/GitLab API search (not just local filter)
2. **Bulk Scanning**: Parallel scanning of multiple repos
3. **Real-time Progress**: WebSocket updates during scans
4. **Persistence**: SQLite caching of repos and results
5. **Export**: JSON/YAML export from results view
6. **Themes**: Configurable color schemes
