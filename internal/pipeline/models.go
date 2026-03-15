package pipeline

import (
	"time"

	"github.com/google/uuid"
)

// --- Attack Surface Models ---

// AttackSurface is the structured output of the recon phase.
type AttackSurface struct {
	CampaignID   uuid.UUID                `json:"campaign_id"`
	Target       string                   `json:"target"`
	Subdomains   []SubdomainRecord        `json:"subdomains"`
	Hosts        []HostRecord             `json:"hosts"`
	Endpoints    []EndpointRecord         `json:"endpoints"`
	Technologies map[string]string        `json:"technologies"`
	CreatedAt    time.Time                `json:"created_at"`
}

// SubdomainRecord represents a discovered subdomain.
type SubdomainRecord struct {
	Domain      string       `json:"domain"`
	IP          string       `json:"ip,omitempty"`
	CNAME       string       `json:"cname,omitempty"`
	HTTPDetails *HTTPDetails `json:"http_details,omitempty"`
	Source      string       `json:"source"`
}

// HostRecord represents a discovered host/IP.
type HostRecord struct {
	IP        string                   `json:"ip"`
	Hostnames []string                 `json:"hostnames"`
	OpenPorts []int                    `json:"open_ports"`
	Services  map[int]ServiceRecord    `json:"services"`
	OS        string                   `json:"os,omitempty"`
	Tags      []string                 `json:"tags,omitempty"`
}

// ServiceRecord represents a service running on a port.
type ServiceRecord struct {
	Port        int          `json:"port"`
	Protocol    string       `json:"protocol"`
	Name        string       `json:"name"`
	Version     string       `json:"version,omitempty"`
	Banner      string       `json:"banner,omitempty"`
	HTTPDetails *HTTPDetails `json:"http_details,omitempty"`
}

// HTTPDetails contains HTTP-specific information about an endpoint.
type HTTPDetails struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Title          string            `json:"title,omitempty"`
	Server         string            `json:"server,omitempty"`
	Technologies   []string          `json:"technologies,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	ResponseBodyHash string          `json:"response_body_hash,omitempty"`
}

// EndpointRecord represents a discovered web endpoint.
type EndpointRecord struct {
	URL         string   `json:"url"`
	Method      string   `json:"method,omitempty"`
	Parameters  []string `json:"parameters,omitempty"`
	StatusCode  int      `json:"status_code,omitempty"`
	Interesting bool     `json:"interesting,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

// --- Finding Models ---

// RawFinding is an unclassified finding from a security tool.
type RawFinding struct {
	ID           uuid.UUID `json:"id"`
	CampaignID   uuid.UUID `json:"campaign_id"`
	Source       string    `json:"source"`
	Type         string    `json:"type"`
	Target       string    `json:"target"`
	Detail       string    `json:"detail"`
	RawOutput    string    `json:"raw_output,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// ClassifiedFinding is a finding enriched with CVE, CVSS, and severity data.
type ClassifiedFinding struct {
	ID                     uuid.UUID  `json:"id"`
	RawFindingID           uuid.UUID  `json:"raw_finding_id"`
	CampaignID             uuid.UUID  `json:"campaign_id"`
	Title                  string     `json:"title"`
	Description            string     `json:"description"`
	CVEIDs                 []string   `json:"cve_ids,omitempty"`
	CVSSScore              float64    `json:"cvss_score"`
	CVSSVector             string     `json:"cvss_vector,omitempty"`
	Severity               Severity   `json:"severity"`
	AttackCategory         string     `json:"attack_category"`
	Confidence             Confidence `json:"confidence"`
	FalsePositiveProbability float64  `json:"false_positive_probability"`
	ChainCandidates        []uuid.UUID `json:"chain_candidates,omitempty"`
	Evidence               []Evidence  `json:"evidence"`
	Target                 string     `json:"target"`
	ClassifiedAt           time.Time  `json:"classified_at"`
}

// Evidence represents proof of a finding.
type Evidence struct {
	Type        string    `json:"type"` // command_output, screenshot, log, http_response
	Content     string    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description,omitempty"`
}

// ClassifiedFindingSet is the output of the classifier agent.
type ClassifiedFindingSet struct {
	CampaignID uuid.UUID            `json:"campaign_id"`
	Findings   []ClassifiedFinding  `json:"findings"`
	Summary    ClassificationSummary `json:"summary"`
	CreatedAt  time.Time            `json:"created_at"`
}

// ClassificationSummary provides aggregate stats about classified findings.
type ClassificationSummary struct {
	TotalFindings int              `json:"total_findings"`
	BySeverity    map[Severity]int `json:"by_severity"`
	TopCategories []string         `json:"top_categories"`
	FilteredAsFP  int             `json:"filtered_as_fp"`
}

// --- Attack Plan Models ---

// AttackPlan is the output of the exploit agent.
type AttackPlan struct {
	ID                uuid.UUID    `json:"id"`
	CampaignID        uuid.UUID    `json:"campaign_id"`
	Paths             []AttackPath `json:"paths"`
	RecommendedPathID uuid.UUID    `json:"recommended_path_id"`
	Reasoning         string       `json:"reasoning"`
	CreatedAt         time.Time    `json:"created_at"`
}

// AttackPath is a sequence of steps to exploit a chain of findings.
type AttackPath struct {
	ID                          uuid.UUID    `json:"id"`
	Name                        string       `json:"name"`
	Description                 string       `json:"description"`
	Steps                       []AttackStep `json:"steps"`
	TargetFindingIDs            []uuid.UUID  `json:"target_finding_ids"`
	EstimatedSuccessProbability float64      `json:"estimated_success_probability"`
	RequiredPrivileges          string       `json:"required_privileges,omitempty"`
	ExpectedImpact              string       `json:"expected_impact"`
}

// AttackStep is a single action in an attack path.
type AttackStep struct {
	ID                   uuid.UUID  `json:"id"`
	Name                 string     `json:"name"`
	TechniqueID          string     `json:"technique_id,omitempty"` // MITRE ATT&CK
	Command              string     `json:"command"`
	ExpectedOutputPattern string   `json:"expected_output_pattern,omitempty"`
	OnSuccessStepID      *uuid.UUID `json:"on_success_step_id,omitempty"`
	OnFailureStepID      *uuid.UUID `json:"on_failure_step_id,omitempty"`
	CleanupCommand       string     `json:"cleanup_command,omitempty"`
}

// ExecutionResult records the outcome of executing an attack step.
type ExecutionResult struct {
	StepID          uuid.UUID  `json:"step_id"`
	CampaignID      uuid.UUID  `json:"campaign_id"`
	CommandExecuted string     `json:"command_executed"`
	Output          string     `json:"output"`
	Success         bool       `json:"success"`
	Evidence        []Evidence `json:"evidence"`
	ExecutedAt      time.Time  `json:"executed_at"`
	DurationMs      int        `json:"duration_ms"`
}

// --- Report Models ---

// PentestReport is the final output of a campaign.
type PentestReport struct {
	ID               uuid.UUID         `json:"id"`
	CampaignID       uuid.UUID         `json:"campaign_id"`
	Target           string            `json:"target"`
	Objective        string            `json:"objective"`
	ExecutiveSummary string            `json:"executive_summary"`
	ScopeDescription string            `json:"scope_description"`
	Methodology      string            `json:"methodology"`
	Findings         []ReportFinding   `json:"findings"`
	AttackNarrative  string            `json:"attack_narrative"`
	RiskSummary      RiskSummary       `json:"risk_summary"`
	RemediationPlan  []RemediationItem `json:"remediation_plan"`
	GeneratedAt      time.Time         `json:"generated_at"`
}

// ReportFinding is a finding formatted for the report.
type ReportFinding struct {
	ID                 uuid.UUID `json:"id"`
	Title              string    `json:"title"`
	Severity           Severity  `json:"severity"`
	CVSSScore          float64   `json:"cvss_score"`
	CVSSVector         string    `json:"cvss_vector,omitempty"`
	Description        string    `json:"description"`
	Evidence           []Evidence `json:"evidence"`
	AffectedComponents []string  `json:"affected_components"`
	Remediation        string    `json:"remediation"`
	References         []string  `json:"references,omitempty"`
	ProofOfConcept     string    `json:"proof_of_concept,omitempty"`
}

// RiskSummary provides an overview of risk levels.
type RiskSummary struct {
	OverallRisk   string `json:"overall_risk"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	LowCount      int    `json:"low_count"`
	InfoCount     int    `json:"info_count"`
}

// RemediationItem is a prioritized remediation action.
type RemediationItem struct {
	Priority int    `json:"priority"`
	Finding  string `json:"finding"`
	Action   string `json:"action"`
	Effort   string `json:"effort"`
	Impact   string `json:"impact"`
}
