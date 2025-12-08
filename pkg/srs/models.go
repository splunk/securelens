package srs

// SRSSubmitResponse represents the response from SRS job submission
type SRSSubmitResponse struct {
	JobStatusURL string `json:"job_status_url"`
}

// SRSJobResponse represents the response when polling job status
type SRSJobResponse struct {
	ServiceResponse ServiceResponse `json:"service_response"`
}

// ServiceResponse contains the list of jobs
type ServiceResponse struct {
	Jobs []Job `json:"jobs"`
}

// Job represents a single scanner job in the SRS response
type Job struct {
	JobID     string `json:"jobid"`
	Resource  string `json:"resource"`
	Results   string `json:"results_string"` // JSON string that needs to be unmarshaled
	Service   string `json:"service"`
	Status    string `json:"status"` // PENDING, RUNNING, COMPLETE, FAILED
	Timestamp string `json:"timestamp"`
}

// JobStatus constants
const (
	JobStatusPending  = "PENDING"
	JobStatusRunning  = "RUNNING"
	JobStatusComplete = "COMPLETE"
	JobStatusFailed   = "FAILED"
)

// IsTerminal returns true if the job status is a terminal state
func (j *Job) IsTerminal() bool {
	return j.Status == JobStatusComplete || j.Status == JobStatusFailed
}

// SemgrepResults represents parsed Semgrep scan results
type SemgrepResults struct {
	Results struct {
		Errors                 []interface{}    `json:"errors"`
		InterfileLanguagesUsed []interface{}    `json:"interfile_languages_used"`
		Paths                  SemgrepPaths     `json:"paths"`
		Results                []SemgrepFinding `json:"results"`
		SkippedRules           []interface{}    `json:"skipped_rules"`
		Version                string           `json:"version"`
	} `json:"results"`
}

type SemgrepPaths struct {
	Scanned []string `json:"scanned"`
}

type SemgrepFinding struct {
	CheckID string `json:"check_id"`
	End     struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		EngineKind  string `json:"engine_kind"`
		Fingerprint string `json:"fingerprint"`
		IsIgnored   bool   `json:"is_ignored"`
		Lines       string `json:"lines"`
		Message     string `json:"message"`
		Metadata    struct {
			CWE        interface{} `json:"cwe"`
			OWASP      interface{} `json:"owasp"`
			References []string    `json:"references"`
		} `json:"metadata"`
		Severity        string `json:"severity"`
		ValidationState string `json:"validation_state"`
	} `json:"extra"`
	Path  string `json:"path"`
	Start struct {
		Col    int `json:"col"`
		Line   int `json:"line"`
		Offset int `json:"offset"`
	} `json:"start"`
}

// TrufflehogResults represents parsed Trufflehog scan results
type TrufflehogResults struct {
	Bytes             int64              `json:"bytes"`
	Chunks            int64              `json:"chunks"`
	Findings          []TrufflehogSecret `json:"findings"`
	Level             string             `json:"level"`
	Logger            string             `json:"logger"`
	Msg               string             `json:"msg"`
	ScanDuration      string             `json:"scan_duration"`
	TrufflehogVersion string             `json:"trufflehog_version"`
	Ts                string             `json:"ts"`
	UnverifiedSecrets int64              `json:"unverified_secrets"`
	VerifiedSecrets   int64              `json:"verified_secrets"`
}

type TrufflehogSecret struct {
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit     string `json:"commit"`
				File       string `json:"file"`
				Email      string `json:"email"`
				Repository string `json:"repository"`
				Timestamp  string `json:"timestamp"`
				Line       int64  `json:"line"`
				Link       string `json:"link"`
				Visibility string `json:"visibility"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	SourceID     int64  `json:"SourceID"`
	SourceType   int64  `json:"SourceType"`
	SourceName   string `json:"SourceName"`
	DetectorType int64  `json:"DetectorType"`
	DetectorName string `json:"DetectorName"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	RawV2        string `json:"RawV2"`
	Redacted     string `json:"Redacted"`
	ExtraData    string `json:"ExtraData"`
}

// FossaResults represents parsed FOSSA scan results
type FossaResults struct {
	Issues []FossaIssue `json:"issues"`
}

type FossaIssue struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	FixedVersion string `json:"fixed_version"`
	CVE          string `json:"cve"`
	Description  string `json:"description"`
}

// TrivyResults represents parsed Trivy scan results
type TrivyResults struct {
	RawData         TrivyRawData                  `json:"raw_data"`
	Vulnerabilities map[string]TrivyVulnerability `json:"vulnerabilities"`
	Packages        map[string]TrivyPackage       `json:"packages"`
}

type TrivyRawData struct {
	ArtifactName string              `json:"ArtifactName"`
	ArtifactType string              `json:"ArtifactType"`
	CreatedAt    string              `json:"CreatedAt"`
	Metadata     TrivyMetadata       `json:"Metadata"`
	Results      []TrivyResultDetail `json:"Results"`
}

type TrivyMetadata struct {
	Author    string `json:"Author"`
	Branch    string `json:"Branch"`
	Commit    string `json:"Commit"`
	CommitMsg string `json:"CommitMsg"`
	Committer string `json:"Committer"`
}

type TrivyResultDetail struct {
	Class           string               `json:"Class"`
	Target          string               `json:"Target"`
	Type            string               `json:"Type"`
	Packages        []TrivyPackageDetail `json:"Packages"`
	Vulnerabilities []TrivyVulnDetail    `json:"Vulnerabilities"`
}

type TrivyPackageDetail struct {
	ID       string   `json:"ID"`
	Name     string   `json:"Name"`
	Version  string   `json:"Version"`
	Licenses []string `json:"Licenses"`
}

type TrivyVulnDetail struct {
	VulnerabilityID  string                    `json:"VulnerabilityID"`
	PkgName          string                    `json:"PkgName"`
	InstalledVersion string                    `json:"InstalledVersion"`
	FixedVersion     string                    `json:"FixedVersion"`
	Severity         string                    `json:"Severity"`
	Description      string                    `json:"Description"`
	PrimaryURL       string                    `json:"PrimaryURL"`
	References       []string                  `json:"References"`
	CVSS             map[string]TrivyCVSSScore `json:"CVSS"`
	CweIDs           []string                  `json:"CweIDs"`
	Title            string                    `json:"Title"`
	Status           string                    `json:"Status"`
	PublishedDate    string                    `json:"PublishedDate"`
	LastModifiedDate string                    `json:"LastModifiedDate"`
}

type TrivyCVSSScore struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
}

type TrivyVulnerability struct {
	CVE              string                    `json:"cve"`
	Name             string                    `json:"name"`
	Version          string                    `json:"version"`
	Severity         string                    `json:"severity"`
	FixVersion       string                    `json:"fix_version"`
	Description      string                    `json:"description"`
	PrimaryURL       string                    `json:"primary_url"`
	References       []string                  `json:"references"`
	CVSS             map[string]TrivyCVSSScore `json:"cvss"`
	CWE              []string                  `json:"cwe"`
	Status           string                    `json:"status"`
	PublishedDate    string                    `json:"published_date"`
	LastModifiedDate string                    `json:"last_modified_date"`
	Title            string                    `json:"title"`
}

type TrivyPackage struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Licenses []string `json:"licenses"`
	Paths    []struct {
		Target string `json:"target"`
		Type   string `json:"type"`
	} `json:"paths"`
}
