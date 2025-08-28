package main

import (
	"context"
	"encoding/json"
	"fmt"

	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/duffney/copacetic-mcp/internal/util"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"
)

const (
	defaultVexFile = "vex.json"
	patchedSuffix  = "-patched"
	// ExecutionMode modes
	ModeComprehensive = "comprehensive"
	ModeReportBased   = "report-based"
)

type ExecutionMode string

const ()

func determineExecutionMode(params PatchParams) ExecutionMode {
	switch {
	case params.Scan:
		return ModeReportBased
	default:
		return ModeComprehensive
	}
}

/*
	TODO: Patch all local images and overwrite current tag
	TODO: Scan tool, return vulns wit sev.
	TODO: Run mcp server from a container to avoid having to install/config tools
	TODO: Integrate with contagious and patch entire registry
*/

type CopaOptions struct {
	ReportPath *string
	Mode       ExecutionMode
	Image      *string
}

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

func Version(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[Ver]) (*mcp.CallToolResultFor[any], error) {
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
func Patch(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[PatchParams]) (*mcp.CallToolResultFor[any], error) {
	// Input validation
	if params.Arguments.Image == "" {
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: "image parameter is required"}},
		}, fmt.Errorf("image parameter is required")
	}

	// Determine execution mode
	mode := determineExecutionMode(params.Arguments)
	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   fmt.Sprintf("Using execution mode: %s", mode),
		Level:  "debug",
		Logger: "copapatch",
	})

	return patchImage(ctx, cc, params.Arguments, mode)
}

func patchImage(ctx context.Context, cc *mcp.ServerSession, params PatchParams, mode ExecutionMode) (*mcp.CallToolResultFor[any], error) {
	var reportPath, vexPath string
	var patchedImage []string
	var numFixedVulns, updatedPackageCount int
	var err error

	switch mode {
	case ModeComprehensive:
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

		_, patchedImage, err = runCopa(ctx, cc, params, reportPath)
		if err != nil {
			log.Fatalf("copa patch all failed: %w", err)
		}

	case ModeReportBased:
		// Scan using the host platform
		reportPath, err = runTrivy(ctx, cc, params.Image, params.Platform)
		if err != nil {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}

		vexPath, patchedImage, err = runCopa(ctx, cc, params, reportPath)
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

	// TODO: add mulit-platform images to new patched tag output
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

func buildPatchResult(originalImage, reportPath, vexPath string, patchedImage []string, numFixedVulns, updatedPackageCount int, scanPerformed bool) *PatchResult {
	return &PatchResult{
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

func formatPatchSuccess(result *PatchResult) string {
	var lines []string
	// TODO: Add platforms if used
	lines = append(lines, fmt.Sprintf("Successfully patched image: %s", result.OriginalImage))

	if result.VexGenerated {
		lines = append(lines, fmt.Sprintf("Vulnerabilities fixed: %d", result.NumFixedVulns))
		lines = append(lines, fmt.Sprintf("Packages updated: %d", result.UpdatedPackageCount))
	}

	lines = append(lines, fmt.Sprintf("New patched image: %s", strings.Join(result.PatchedImage, ",")))

	return strings.Join(lines, "\n")
}

func runTrivy(ctx context.Context, cc *mcp.ServerSession, image string, platform []string) (reportPath string, err error) {
	reportPath, err = os.MkdirTemp(os.TempDir(), "reports-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary report directory: %w", err)
	}
	trivyArgs := []string{
		"image",
		"--vuln-type", "os",
		"--ignore-unfixed",
		"-f", "json",
	}
	trivyArgs = append(trivyArgs, image)

	if len(platform) == 0 {
		trivyArgs = append(trivyArgs, "-o", filepath.Join(reportPath, "report.json"))
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   "executing: " + strings.Join(append([]string{"trivy "}, trivyArgs...), " "),
			Level:  "debug",
			Logger: "copapatch",
		})

		trivyCmd := exec.Command("trivy", trivyArgs...)
		var stderrTrivy strings.Builder
		trivyCmd.Stderr = &stderrTrivy

		err = trivyCmd.Run()
		if err != nil {
			exitCode := ""
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
			}
			errorMsg := fmt.Sprintf("trivy command failed%s: %v|n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf(errorMsg)
		}

		return reportPath, nil
	}

	for _, p := range platform {
		args := trivyArgs
		args = append(args, "--platform", p)
		args = append(args, "-o", filepath.Join(reportPath, strings.ReplaceAll(p, "/", "-")+".json"))

		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   "executing: " + strings.Join(append([]string{"trivy "}, args...), " "),
			Level:  "debug",
			Logger: "copapatch",
		})

		trivyCmd := exec.Command("trivy", args...)
		var stderrTrivy strings.Builder
		trivyCmd.Stderr = &stderrTrivy

		err = trivyCmd.Run()
		if err != nil {
			exitCode := ""
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
			}
			errorMsg := fmt.Sprintf("trivy command failed%s: %v|n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf(errorMsg)
		}
	}

	return reportPath, nil
}

func runCopa(ctx context.Context, cc *mcp.ServerSession, params PatchParams, reportPath string) (vexPath string, patchedImage []string, err error) {
	var tag, repository string
	ref, err := name.ParseReference(params.Image)
	if err != nil {
		return "", []string{}, fmt.Errorf("failed to parse image reference %s: %w", params.Image, err)
	}

	// TODO: support digests
	if tagged, ok := ref.(name.Tag); ok {
		tag = tagged.TagStr()
		repository = tagged.Repository.RepositoryStr()
		repository = strings.TrimPrefix(repository, "library/")
	}

	copaArgs := []string{
		"patch",
		"--image", params.Image,
	}

	// "VEX output requires a vulnerability report. If -r <report_file> flag is not specified (the "update all" mode), no VEX document is generated.
	if reportPath != "" {
		vexPath = filepath.Join(os.TempDir(), defaultVexFile)
		copaArgs = append(copaArgs, "--report", reportPath)
		copaArgs = append(copaArgs, "--output", vexPath)
	}

	if params.Tag != "" {
		copaArgs = append(copaArgs, "--tag", params.Tag)
		patchedImage = []string{fmt.Sprintf("%s:%s", repository, params.Tag)}
	} else {
		params.Tag = tag + patchedSuffix
	}

	if params.Tag == "" && len(params.Platform) <= 0 {
		patchedImage = []string{fmt.Sprintf("%s:%s", repository, params.Tag)}
	}

	if len(params.Platform) > 0 {
		for _, p := range params.Platform {
			arch := platformToArch(p)
			// patchedImage = append(patchedImage, strings.Join([]string{params.Tag}, arch))
			patchedImage = append(patchedImage, fmt.Sprintf("%s:%s-%s", repository, params.Tag, arch))
		}
	}

	// TODO: add msg: when mulit-platform creating image index
	if params.Push {
		copaArgs = append(copaArgs, "--push")
	}

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   "Executing: " + strings.Join(append([]string{"copa "}, copaArgs...), " "),
		Level:  "debug",
		Logger: "copapatch",
	})

	copaCmd := exec.Command("copa", copaArgs...)
	var stderr strings.Builder
	copaCmd.Stderr = &stderr
	err = copaCmd.Run()
	if err != nil {
		exitCode := ""
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
		}
		errorMsg := fmt.Sprintf("Copa command failed%s: %v\n%s", exitCode, err, stderr.String())
		return "", []string{}, fmt.Errorf(errorMsg)
	}
	return vexPath, patchedImage, nil
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

func platformToArch(platform string) string {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return platform // fallback if invalid format
	}

	arch := parts[1] // e.g., "amd64", "arm", "arm64"

	if len(parts) > 2 {
		// Handle cases like linux/arm/v6, linux/arm/v7
		variant := parts[2]
		return arch + "-" + variant
	}

	return arch
}

func main() {
	// Create a server with a single tool.
	server := mcp.NewServer(&mcp.Implementation{Name: "", Version: "v1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "version", Description: "Copacetic automated container pactching"}, Version)
	mcp.AddTool(server, &mcp.Tool{Name: "patch", Description: "Pacth container image with copacetic"}, Patch)
	// Run the server over stdin/stdout, until the client disconnects
	if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
		log.Fatal(err)
	}
}
