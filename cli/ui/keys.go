package ui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines the key bindings for the TUI
type KeyMap struct {
	// Navigation
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	PageUp   key.Binding
	PageDown key.Binding

	// Actions
	Enter  key.Binding
	Space  key.Binding
	Escape key.Binding
	Back   key.Binding

	// Global
	Quit       key.Binding
	Help       key.Binding
	Search     key.Binding
	SelectAll  key.Binding
	SelectNone key.Binding
	Refresh    key.Binding
	LoadMore   key.Binding
	AddRepoURL key.Binding

	// View jumping
	GoHome    key.Binding
	GoRepos   key.Binding
	GoResults key.Binding

	// Results actions
	Export     key.Binding
	ExportYAML key.Binding
	Rescan     key.Binding

	// Tab navigation
	Tab      key.Binding
	ShiftTab key.Binding
}

// DefaultKeyMap returns the default key bindings
func DefaultKeyMap() KeyMap {
	return KeyMap{
		// Navigation
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "left"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "right"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+u"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+d"),
			key.WithHelp("pgdn", "page down"),
		),

		// Actions
		Enter: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select/confirm"),
		),
		Space: key.NewBinding(
			key.WithKeys(" "),
			key.WithHelp("space", "toggle"),
		),
		Escape: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
		Back: key.NewBinding(
			key.WithKeys("backspace", "b"),
			key.WithHelp("b", "back"),
		),

		// Global
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Search: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "search"),
		),
		SelectAll: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "select all"),
		),
		SelectNone: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "select none"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r", "ctrl+r"),
			key.WithHelp("r", "refresh"),
		),
		LoadMore: key.NewBinding(
			key.WithKeys("m", "ctrl+m"),
			key.WithHelp("m", "load more"),
		),
		AddRepoURL: key.NewBinding(
			key.WithKeys("+", "u"),
			key.WithHelp("+/u", "add repo URL"),
		),

		// View jumping
		GoHome: key.NewBinding(
			key.WithKeys("1"),
			key.WithHelp("1", "home"),
		),
		GoRepos: key.NewBinding(
			key.WithKeys("2"),
			key.WithHelp("2", "repos"),
		),
		GoResults: key.NewBinding(
			key.WithKeys("3"),
			key.WithHelp("3", "results"),
		),

		// Results actions
		Export: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "export JSON"),
		),
		ExportYAML: key.NewBinding(
			key.WithKeys("y"),
			key.WithHelp("y", "export YAML"),
		),
		Rescan: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "scan"),
		),

		// Tab navigation
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next tab"),
		),
		ShiftTab: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", "prev tab"),
		),
	}
}

// ShortHelp returns key bindings for the short help view
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Quit, k.Help}
}

// FullHelp returns key bindings for the full help view
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.PageUp, k.PageDown},
		{k.Enter, k.Space, k.Escape, k.Back},
		{k.Search, k.SelectAll, k.SelectNone, k.Refresh},
		{k.GoHome, k.GoRepos, k.GoResults, k.Quit},
	}
}
