package ui

import (
	"github.com/splunk/securelens/cli/scan"
)

// ViewType represents the current view in the TUI
type ViewType int

const (
	ViewHome ViewType = iota
	ViewRepos
	ViewScan
	ViewResults
	ViewWizard
)

func (v ViewType) String() string {
	return [...]string{"Home", "Repositories", "Scanning", "Results", "Setup"}[v]
}

// Custom messages for the TUI

// WindowSizeMsg is sent when the terminal is resized
type WindowSizeMsg struct {
	Width  int
	Height int
}

// ChangeViewMsg requests a view change
type ChangeViewMsg struct {
	View ViewType
}

// ErrorMsg represents an error
type ErrorMsg struct {
	Err error
}

func (e ErrorMsg) Error() string {
	return e.Err.Error()
}

// StatusMsg represents a status update
type StatusMsg string

// ReposLoadedMsg is sent when repositories are loaded
type ReposLoadedMsg struct {
	Repos []scan.DiscoveredRepository
	Limit int // The limit that was requested (for pagination tracking)
}

// ReposLoadingMsg indicates repos are being loaded
type ReposLoadingMsg struct{}

// ScanStartMsg starts a scan
type ScanStartMsg struct {
	Repos []scan.DiscoveredRepository
}

// ScanProgressMsg reports scan progress
type ScanProgressMsg struct {
	RepoIndex     int
	RepoName      string
	Scanner       string
	Status        string // "running", "complete", "error"
	Message       string
	FindingsCount int
}

// ScanCompleteMsg indicates scan completion
type ScanCompleteMsg struct {
	Report *scan.ScanReport
	Error  error
}

// BulkScanCompleteMsg indicates all bulk scans complete
type BulkScanCompleteMsg struct {
	Reports []*scan.ScanReport
	Errors  []error
}

// ReportLoadedMsg is sent when a report is loaded
type ReportLoadedMsg struct {
	Report *scan.ScanReport
}

// ConfigSavedMsg indicates config was saved
type ConfigSavedMsg struct {
	Path string
}

// ProviderTestMsg is result of testing a provider connection
type ProviderTestMsg struct {
	Provider string
	Success  bool
	Message  string
}
