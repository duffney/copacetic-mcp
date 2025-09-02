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
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"
)

// NewServer creates and configures the MCP server with all tools
func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "copacetic-mcp",
		Version: "v1.0.0",
	}, nil)

	// Register tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "version",
		Description: "Copacetic automated container patching",
	}, Version)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "patch",
		Description: "Patch container image with copacetic",
	}, Patch)

	return server
}

// Run starts the MCP server
func Run(ctx context.Context) error {
	server := NewServer()
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
	}

	if len(result.PatchedImage) > 0 {
		images := strings.Join(result.PatchedImage, ", ")
		lines = append(lines, fmt.Sprintf("New patched image(s): %s", images))
	} else {
		lines = append(lines, fmt.Sprintf("New patched image(s): %s", result.PatchedImage))
	}

	return strings.Join(lines, "\n")
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
