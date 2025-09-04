package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/duffney/copacetic-mcp/internal/copa"
	"github.com/duffney/copacetic-mcp/internal/trivy"
	"github.com/duffney/copacetic-mcp/internal/types"
	multiplatform "github.com/duffney/copacetic-mcp/internal/util"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"
)

// NewServer creates and configures the MCP server with all tools
func NewServer(version string) *mcp.Server {
	if version == "" {
		version = "dev"
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "copacetic-mcp",
		Version: version,
	}, nil)

	// Register tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "version",
		Description: "Copacetic automated container patching",
	}, Version)

	// Workflow guidance tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "workflow-guide",
		Description: "Get guidance on which Copacetic tools to use for different container patching scenarios",
	}, WorkflowGuide)

	// Vulnerability scanning tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan-container",
		Description: "Scan container image for vulnerabilities using Trivy - creates vulnerability reports required for report-based patching",
	}, ScanContainer)

	// Legacy patch tool for backward compatibility
	// mcp.AddTool(server, &mcp.Tool{
	// Name:        "patch",
	// Description: "Patch container image with copacetic (legacy - use specific patching tools instead)",
	// }, Patch)

	// New focused patching tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "patch-vulnerabilities",
		Description: "Patch container image vulnerabilities using a pre-generated vulnerability report from 'scan-container' tool - requires running 'scan-container' first. This is the RECOMMENDED approach for vulnerability-based patching.",
	}, PatchVulnerabilities)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "patch-platforms",
		Description: "Patch specific container image platforms with Copa - patches only the specified platforms WITHOUT vulnerability scanning. Use ONLY when you want to patch specific platforms regardless of vulnerabilities. For vulnerability-based patching, use 'scan-container' + 'patch-vulnerabilities'.",
	}, PatchPlatforms)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "patch-comprehensive",
		Description: "Comprehensively patch all container image platforms with Copa - patches all available platforms WITHOUT vulnerability scanning. Use ONLY when you want to patch all platforms regardless of vulnerabilities. For vulnerability-based patching, use 'scan-container' + 'patch-vulnerabilities'.",
	}, PatchComprehensive)

	return server
}

// Run starts the MCP server
func Run(ctx context.Context, version string) error {
	server := NewServer(version)
	return server.Run(ctx, mcp.NewStdioTransport())
}

func Version(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.Ver]) (*mcp.CallToolResultFor[any], error) {
	cmd := exec.Command("copa", "--version")
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	params.Arguments.Version = string(output)
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: params.Arguments.Version}},
	}, nil
}

func WorkflowGuide(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[map[string]interface{}]) (*mcp.CallToolResultFor[any], error) {
	guidance := getWorkflowGuidance()
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: guidance}},
	}, nil
}

// ScanContainer performs vulnerability scanning on a container image using Trivy
func ScanContainer(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.ScanParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Starting vulnerability scan for image: %s", params.Arguments.Image),
		Level:  "info",
		Logger: "trivy",
	})

	// Perform the vulnerability scan
	scanResult, err := trivy.Scan(ctx, cc, params.Arguments)
	if err != nil {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vulnerability scan failed: %v", err)}},
		}, err
	}

	// Format the scan results with clearer workflow guidance
	var resultMsg strings.Builder
	resultMsg.WriteString(fmt.Sprintf("Vulnerability scan completed for image: %s\n", scanResult.Image))
	resultMsg.WriteString(fmt.Sprintf("Total vulnerabilities found: %d\n", scanResult.VulnCount))
	resultMsg.WriteString(fmt.Sprintf("Scanned platforms: %s\n", strings.Join(scanResult.Platforms, ", ")))
	resultMsg.WriteString(fmt.Sprintf("Report directory: %s\n", scanResult.ReportPath))
	resultMsg.WriteString("\n=== NEXT STEPS ===")
	resultMsg.WriteString("\nTo patch vulnerabilities found in this scan, use the 'patch-vulnerabilities' tool with the above report directory path.")
	resultMsg.WriteString("\n\nNOTE: Do NOT use 'patch-platforms' or 'patch-comprehensive' if you want to patch based on these scan results.")
	resultMsg.WriteString("\nThose tools are for patching WITHOUT vulnerability scanning.")

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: resultMsg.String()}},
	}, nil
}

// TODO: feat: make images []string and loop through for patching in parallel
func Patch(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.PatchParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	// Determine execution mode
	mode := types.DetermineExecutionMode(params.Arguments)
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Using execution mode: %s", mode),
		Level:  "debug",
		Logger: "copapatch",
	})

	return patchImage(ctx, cc, params.Arguments, mode)
}

// PatchVulnerabilities performs report-based patching using an existing vulnerability report
// NOTE: This tool requires that 'scan-container' has been run first to generate the vulnerability report
func PatchVulnerabilities(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.ReportBasedPatchParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	if params.Arguments.ReportPath == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "reportPath parameter is required. You must run the 'scan-container' tool first to generate a vulnerability report, then provide the report directory path here."}},
		}, fmt.Errorf("reportPath parameter is required - run 'scan-container' tool first")
	}

	// Verify the report path exists and contains reports
	if _, err := os.Stat(params.Arguments.ReportPath); os.IsNotExist(err) {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Report directory does not exist: %s. Please run 'scan-container' tool first to generate vulnerability reports.", params.Arguments.ReportPath)}},
		}, fmt.Errorf("report directory does not exist: %s", params.Arguments.ReportPath)
	}

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Using existing vulnerability report for patching: %s", params.Arguments.ReportPath),
		Level:  "info",
		Logger: "copapatch",
	})

	return patchImageReportBased(ctx, cc, params.Arguments)
}

// PatchPlatforms performs platform-selective patching
// NOTE: This tool should only be used when NO vulnerability scanning is desired and specific platforms need patching
// If you want to patch based on vulnerability scan results, use 'patch-vulnerabilities' instead
func PatchPlatforms(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.PlatformSelectivePatchParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	if len(params.Arguments.Platform) == 0 {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "at least one platform must be specified for platform-selective patching"}},
		}, fmt.Errorf("at least one platform must be specified for platform-selective patching")
	}

	// Workflow validation - warn if this might not be the intended tool
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   "Using platform-selective patching - this will patch specified platforms WITHOUT vulnerability scanning. If you want to patch based on scan results, use 'scan-container' followed by 'patch-vulnerabilities' instead.",
		Level:  "info",
		Logger: "copapatch",
	})

	supportedPlatforms := multiplatform.FilterSupportedPlatforms(params.Arguments.Platform)
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Using platform-selective patching for platforms: %s", strings.Join(supportedPlatforms, ", ")),
		Level:  "debug",
		Logger: "copapatch",
	})

	return patchImagePlatformSelective(ctx, cc, params.Arguments)
}

// PatchComprehensive performs comprehensive patching of all available platforms
// NOTE: This tool patches ALL available platforms WITHOUT vulnerability scanning
// If you want to patch based on vulnerability scan results, use 'scan-container' followed by 'patch-vulnerabilities' instead
func PatchComprehensive(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[types.ComprehensivePatchParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	// Workflow validation - warn about comprehensive patching approach
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   "Using comprehensive patching - this will patch ALL available platforms WITHOUT vulnerability scanning. If you want to patch based on scan results, use 'scan-container' followed by 'patch-vulnerabilities' instead.",
		Level:  "info",
		Logger: "copapatch",
	})

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   "Using comprehensive patching - will patch all available platforms",
		Level:  "debug",
		Logger: "copapatch",
	})

	return patchImageComprehensive(ctx, cc, params.Arguments)
}

func patchImage(ctx context.Context, cc *mcp.ServerSession, params types.PatchParams, mode types.ExecutionMode) (*mcp.CallToolResultFor[any], error) {
	var reportPath, vexPath string
	var patchedImage []string
	var numFixedVulns, updatedPackageCount int
	var err error

	switch mode {
	case types.ModeComprehensive:
		imageDetails, err := multiplatform.GetImageInfo(ctx, params.Image)
		if err != nil {
			log.Fatal(err)
		}

		// since the image is local and no platforms were specified, patch and create an image for each of the supported platforms
		if imageDetails.IsLocal && imageDetails.IsMultiPlatform && len(params.Platform) == 0 {
			supportedPlatforms := strings.Join(multiplatform.GetAllSupportedPlatforms(), ", ")
			cc.Log(ctx, &mcp.LoggingMessageParams{
				Data:   fmt.Sprintf("Local multiplatform image detected (%s). Copa will patch all %d supported platforms: %s", params.Image, len(multiplatform.GetAllSupportedPlatforms()), supportedPlatforms),
				Level:  "info",
				Logger: "copapatch",
			})
		}

		// TODO: update msg to compare existing platforms vs supported
		// Use the registry image index to get the platforms, then patch and create an image for each supported platform
		if !imageDetails.IsLocal && imageDetails.IsMultiPlatform && len(params.Platform) == 0 {
			platformsToPatch := multiplatform.FilterSupportedPlatforms(imageDetails.Platform)
			supportedPlatforms := strings.Join(platformsToPatch, ", ")
			cc.Log(ctx, &mcp.LoggingMessageParams{
				Data:   fmt.Sprintf("Remote multiplatform image detected (%s). Copa will patch %d supported platforms: %s", params.Image, len(platformsToPatch), supportedPlatforms),
				Level:  "info",
				Logger: "copapatch",
			})
		}

		if len(params.Platform) > 0 {
			supportedPlatforms := multiplatform.FilterSupportedPlatforms(params.Platform)
			cc.Log(ctx, &mcp.LoggingMessageParams{
				Data:   fmt.Sprintf("patching platforms: %s", supportedPlatforms),
				Level:  "info",
				Logger: "copapatch",
			})
		}

		_, patchedImage, err = copa.Run(ctx, cc, params, reportPath)
		if err != nil {
			log.Fatalf("copa patch all failed: %v", err)
		}

	case types.ModeReportBased:
		// Scan using the host platform
		reportPath, err = trivy.Run(ctx, cc, params.Image, params.Platform)
		if err != nil {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}

		vexPath, patchedImage, err = copa.Run(ctx, cc, params, reportPath)
		if err != nil {
			return nil, fmt.Errorf("copa failed: %w", err)
		}

		numFixedVulns, updatedPackageCount, err = parseVexDoc(vexPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse vex document: %w", err)
		}

		if err := os.RemoveAll(vexPath); err != nil {
			return nil, fmt.Errorf("warning: failed to delete vex file %s: %v", vexPath, err)
		}
		if err := os.RemoveAll(reportPath); err != nil {
			return nil, fmt.Errorf("warning: failed to delete report file %s: %v", reportPath, err)
		}
	}

	result := buildPatchResult(
		params.Image,
		reportPath,
		vexPath,
		patchedImage,
		numFixedVulns,
		updatedPackageCount,
		params.Scan,
	)

	successMsg := formatPatchSuccess(result)

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: successMsg}},
	}, nil
}

// patchImageReportBased handles report-based patching using an existing vulnerability report
func patchImageReportBased(ctx context.Context, cc *mcp.ServerSession, params types.ReportBasedPatchParams) (*mcp.CallToolResultFor[any], error) {
	// Use the provided report path instead of scanning
	reportPath := params.ReportPath

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Using vulnerability report from: %s", reportPath),
		Level:  "info",
		Logger: "copapatch",
	})

	// Patch based on the existing vulnerability report
	vexPath, patchedImage, err := copa.RunReportBased(ctx, cc, params, reportPath)
	if err != nil {
		return nil, fmt.Errorf("copa report-based patching failed: %w", err)
	}

	// Parse VEX document for vulnerability statistics
	numFixedVulns, updatedPackageCount, err := parseVexDoc(vexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vex document: %w", err)
	}

	// Clean up VEX file (keep the original scan report for potential reuse)
	if err := os.RemoveAll(vexPath); err != nil {
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   fmt.Sprintf("Warning: failed to delete vex file %s: %v", vexPath, err),
			Level:  "warn",
			Logger: "copapatch",
		})
	}

	result := buildPatchResult(
		params.Image,
		reportPath,
		vexPath,
		patchedImage,
		numFixedVulns,
		updatedPackageCount,
		true, // scan was performed (previously)
	)

	successMsg := formatPatchSuccess(result)
	successMsg += fmt.Sprintf("\n\nNote: Used existing vulnerability report from: %s", reportPath)

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: successMsg}},
	}, nil
}

// patchImagePlatformSelective handles platform-selective patching
func patchImagePlatformSelective(ctx context.Context, cc *mcp.ServerSession, params types.PlatformSelectivePatchParams) (*mcp.CallToolResultFor[any], error) {
	supportedPlatforms := multiplatform.FilterSupportedPlatforms(params.Platform)
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Patching platforms: %s", strings.Join(supportedPlatforms, ", ")),
		Level:  "info",
		Logger: "copapatch",
	})

	// Patch only the specified platforms
	_, patchedImage, err := copa.RunPlatformSelective(ctx, cc, params)
	if err != nil {
		return nil, fmt.Errorf("copa platform-selective patching failed: %w", err)
	}

	result := buildPatchResult(
		params.Image,
		"", // no report path for platform-selective
		"", // no vex path for platform-selective
		patchedImage,
		0,     // no vulnerability count for platform-selective
		0,     // no package count for platform-selective
		false, // no scan performed
	)

	successMsg := formatPatchSuccess(result)
	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: successMsg}},
	}, nil
}

// patchImageComprehensive handles comprehensive patching of all platforms
func patchImageComprehensive(ctx context.Context, cc *mcp.ServerSession, params types.ComprehensivePatchParams) (*mcp.CallToolResultFor[any], error) {
	imageDetails, err := multiplatform.GetImageInfo(ctx, params.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to get image info: %w", err)
	}

	var expectedPlatforms []string
	var expectedImages []string

	// Determine what platforms will be patched and what images will be created
	if imageDetails.IsLocal && imageDetails.IsMultiPlatform {
		expectedPlatforms = multiplatform.GetAllSupportedPlatforms()
		supportedPlatforms := strings.Join(expectedPlatforms, ", ")
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   fmt.Sprintf("Local multiplatform image detected (%s). Copa will patch all %d supported platforms: %s", params.Image, len(expectedPlatforms), supportedPlatforms),
			Level:  "info",
			Logger: "copapatch",
		})
	} else if !imageDetails.IsLocal && imageDetails.IsMultiPlatform {
		expectedPlatforms = multiplatform.FilterSupportedPlatforms(imageDetails.Platform)
		supportedPlatforms := strings.Join(expectedPlatforms, ", ")
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   fmt.Sprintf("Remote multiplatform image detected (%s). Copa will patch %d supported platforms: %s", params.Image, len(expectedPlatforms), supportedPlatforms),
			Level:  "info",
			Logger: "copapatch",
		})
	} else {
		// Single platform image - use current platform
		expectedPlatforms = []string{fmt.Sprintf("%s/%s", "linux", "amd64")} // Default to common platform
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   fmt.Sprintf("Single platform image detected (%s). Copa will patch for current platform.", params.Image),
			Level:  "info",
			Logger: "copapatch",
		})
	}

	// Calculate expected image names based on platforms and tag
	ref, err := name.ParseReference(params.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", params.Image, err)
	}

	repository := ""
	if tagged, ok := ref.(name.Tag); ok {
		repository = tagged.RepositoryStr()
		repository = strings.TrimPrefix(repository, "library/")
	}

	// Build expected image list
	if len(expectedPlatforms) > 1 || imageDetails.IsMultiPlatform {
		// Multiplatform: each platform gets architecture suffix
		for _, platform := range expectedPlatforms {
			arch := multiplatform.PlatformToArch(platform)
			expectedImages = append(expectedImages, fmt.Sprintf("%s:%s-%s", repository, params.Tag, arch))
		}
	} else {
		// Single platform: exact tag
		expectedImages = []string{fmt.Sprintf("%s:%s", repository, params.Tag)}
	}

	// Patch all available platforms
	_, _, err = copa.RunComprehensive(ctx, cc, params)
	if err != nil {
		return nil, fmt.Errorf("copa comprehensive patching failed: %w", err)
	}

	// Use the expected images for better user communication
	result := buildPatchResult(
		params.Image,
		"",             // no report path for comprehensive
		"",             // no vex path for comprehensive
		expectedImages, // Use predicted images for clearer messaging
		0,              // no vulnerability count for comprehensive
		0,              // no package count for comprehensive
		false,          // no scan performed
	)

	successMsg := formatPatchSuccess(result)

	// Add multiplatform explanation if applicable
	if len(expectedPlatforms) > 1 || imageDetails.IsMultiPlatform {
		exampleArch1 := multiplatform.PlatformToArch(expectedPlatforms[0])
		exampleArch2 := "arm64" // Default second example
		if len(expectedPlatforms) > 1 {
			exampleArch2 = multiplatform.PlatformToArch(expectedPlatforms[1])
		}
		successMsg += fmt.Sprintf("\n\nNote: Multiplatform image detected. Copa creates separate images for each supported platform with architecture suffixes (e.g., -%s, -%s, etc.)",
			exampleArch1, exampleArch2)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: successMsg}},
	}, nil
}

func buildPatchResult(originalImage, reportPath, vexPath string, patchedImage []string, numFixedVulns, updatedPackageCount int, scanPerformed bool) *types.PatchResult {
	return &types.PatchResult{
		OriginalImage:       originalImage,
		PatchedImage:        patchedImage,
		ReportPath:          reportPath,
		VexPath:             vexPath,
		NumFixedVulns:       numFixedVulns,
		UpdatedPackageCount: updatedPackageCount,
		ScanPerformed:       scanPerformed,
		VexGenerated:        vexPath != "",
	}
}

func formatPatchSuccess(result *types.PatchResult) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Successfully patched image: %s", result.OriginalImage))

	if result.VexGenerated {
		lines = append(lines, fmt.Sprintf("Vulnerabilities fixed: %d", result.NumFixedVulns))
		lines = append(lines, fmt.Sprintf("Packages updated: %d", result.UpdatedPackageCount))
		lines = append(lines, "✓ Vulnerability-based patching completed")
	} else {
		lines = append(lines, "✓ Platform-based patching completed (no vulnerability scanning performed)")
	}

	if len(result.PatchedImage) > 0 {
		images := strings.Join(result.PatchedImage, ", ")
		lines = append(lines, fmt.Sprintf("New patched image(s): %s", images))
	} else {
		lines = append(lines, fmt.Sprintf("New patched image(s): %s", result.PatchedImage))
	}

	return strings.Join(lines, "\n")
}

// getWorkflowGuidance provides guidance on which tool to use for different scenarios
func getWorkflowGuidance() string {
	return `
=== COPACETIC WORKFLOW GUIDANCE ===

Choose the right tool for your use case:

1. VULNERABILITY-BASED PATCHING (Recommended):
   Step 1: scan-container (scan for vulnerabilities)
   Step 2: patch-vulnerabilities (patch only found vulnerabilities)
   
2. PLATFORM-SPECIFIC PATCHING (without vulnerability scanning):
   Use: patch-platforms (specify which platforms to patch)
   
3. COMPREHENSIVE PATCHING (without vulnerability scanning):
   Use: patch-comprehensive (patch all available platforms)

IMPORTANT: Do NOT mix approaches. If you scan first, use patch-vulnerabilities.
If you want platform-specific patching without scanning, use patch-platforms.`
}

func parseVexDoc(path string) (numFixedVulns, updatedPackageCount int, err error) {
	vexData, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}

	var doc vex.VEX

	if err := json.Unmarshal(vexData, &doc); err != nil {
		return 0, 0, err
	}

	for _, stmt := range doc.Statements {
		if stmt.Status == vex.StatusFixed {
			numFixedVulns++
			for _, product := range stmt.Products {
				updatedPackageCount += len(product.Subcomponents)
			}
		}
	}
	return numFixedVulns, updatedPackageCount, nil
}
