package types

const (
	ModeComprehensive = "comprehensive"
	ModeReportBased   = "report-based"
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
