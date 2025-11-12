package models

import (
	"time"
)

// OwnershipReference represents repository ownership mapping
type OwnershipReference struct {
	// Primary identification
	ID int `db:"id"`

	// Repository identification
	RepoURL     string `db:"repo_url"`
	RepoPostfix string `db:"repo_postfix"`
	Branch      string `db:"branch"`

	// Ownership details
	OwnerType       string `db:"owner_type"`       // 'user', 'team', 'group'
	OwnerIdentifier string `db:"owner_identifier"` // Email, username, or group name

	// Metadata
	PreferredAssigneeStrategy string `db:"preferred_assignee_strategy"` // 'assignee', 'recent_committer', 'codeowners'
	JiraLabels                string `db:"jira_labels"`                 // Comma-separated
	JiraWatchers              string `db:"jira_watchers"`               // Comma-separated email addresses
	ProductArea               string `db:"product_area"`
	MissionTeam               string `db:"mission_team"`
	O11yProgramTeam           string `db:"o11y_program_team"`

	// Timestamps
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}
