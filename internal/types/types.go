package types

const (
	ModeComprehensive     = "comprehensive"
	ModeReportBased       = "report-based"
	ModePlatformSelective = "platform-selective"
)

type ExecutionMode string

type Ver struct {
	Version string `json:"version" jsonschema:"the version of the copa cli"`
}

type PatchResult struct {
	OriginalImage       string
	PatchedImage        []string
	ReportPath          string
	VexPath             string
	NumFixedVulns       int
	UpdatedPackageCount int
	ScanPerformed       bool
	VexGenerated        bool
}

// Common base parameters shared across all patching tools
type BasePatchParams struct {
	Image string `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag   string `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push  bool   `json:"push" jsonschema:"push patched image to destination registry"`
}

// ReportBasedPatchParams - patches only vulnerabilities found in an existing vulnerability report
// NOTE: This requires a vulnerability scan to be run first using the 'scan-container' tool
type ReportBasedPatchParams struct {
	Image      string `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag        string `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push       bool   `json:"push" jsonschema:"push patched image to destination registry"`
	ReportPath string `json:"reportPath" jsonschema:"Path to the vulnerability report directory created by the 'scan-container' tool. This must be provided - run 'scan-container' first to generate the report."`
}

// PlatformSelectivePatchParams - patches only specified platforms
type PlatformSelectivePatchParams struct {
	Image    string   `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag      string   `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push     bool     `json:"push" jsonschema:"push patched image to destination registry"`
	Platform []string `json:"platform" jsonschema:"Target platform(s) for patching (e.g., linux/amd64,linux/arm64). Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. Only specified platforms will be patched, others will be preserved unchanged"`
}

// ComprehensivePatchParams - patches all available platforms with latest updates
type ComprehensivePatchParams struct {
	Image string `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag   string `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push  bool   `json:"push" jsonschema:"push patched image to destination registry"`
}

// ScanParams - parameters for scanning container images for vulnerabilities
type ScanParams struct {
	Image    string   `json:"image" jsonschema:"the image reference of the container to scan for vulnerabilities"`
	Platform []string `json:"platform,omitempty" jsonschema:"Target platform(s) for vulnerability scanning (e.g., linux/amd64,linux/arm64). Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. If not specified, scans the host platform"`
}

// ScanResult - result of a vulnerability scan
type ScanResult struct {
	Image         string
	ReportPath    string
	VulnCount     int
	Platforms     []string
	ScanCompleted bool
}

// Legacy PatchParams struct kept for backward compatibility
type PatchParams struct {
	Image    string   `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag      string   `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push     bool     `json:"push" jsonschema:"push patched image to destination registry"`
	Scan     bool     `json:"scan" jsonschema:"scan container image to generate vulnerability report using trivy"`
	Platform []string `json:"platform" jsonschema:"Target platform(s) for multi-arch images when no report directory is provided (e.g., linux/amd64,linux/arm64). Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. If platform flag is used, only specified platforms are patched and the rest are preserved. If not specified, all platforms present in the image are patched"`
}

func DetermineExecutionMode(params PatchParams) ExecutionMode {
	switch {
	case params.Scan:
		return ModeReportBased
	default:
		return ModeComprehensive
	}
}

// ConvertToBasePatchParams converts any patch params to BasePatchParams
func ConvertToBasePatchParams(image, tag string, push bool) BasePatchParams {
	return BasePatchParams{
		Image: image,
		Tag:   tag,
		Push:  push,
	}
}
