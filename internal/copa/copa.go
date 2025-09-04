package copa

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/duffney/copacetic-mcp/internal/types"
	multiplatform "github.com/duffney/copacetic-mcp/internal/util"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	patchedSuffix  = "-patched"
	defaultVexFile = "vex.json"
)

func Run(ctx context.Context, cc *mcp.ServerSession, params types.PatchParams, reportPath string) (vexPath string, patchedImage []string, err error) {
	var tag, repository string
	ref, err := name.ParseReference(params.Image)
	if err != nil {
		return "", []string{}, fmt.Errorf("failed to parse image reference %s: %w", params.Image, err)
	}

	// TODO: support digests
	if tagged, ok := ref.(name.Tag); ok {
		tag = tagged.TagStr()
		repository = tagged.RepositoryStr()
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

	// Determine if a custom tag was provided
	customTagProvided := params.Tag != ""

	// For platform-selective patching, we always want platform-specific behavior
	// For vulnerability patching, we want exact tags when custom tag is provided
	usePlatformSpecificTags := len(params.Platform) > 0 && (params.Scan || !customTagProvided)

	if customTagProvided {
		copaArgs = append(copaArgs, "--tag", params.Tag)
		if !usePlatformSpecificTags {
			patchedImage = []string{fmt.Sprintf("%s:%s", repository, params.Tag)}
		}
	} else {
		params.Tag = tag + patchedSuffix
	}

	if params.Tag == "" && len(params.Platform) <= 0 {
		patchedImage = []string{fmt.Sprintf("%s:%s", repository, params.Tag)}
	}

	if usePlatformSpecificTags {
		platformArgs := strings.Join(params.Platform, ",")
		copaArgs = append(copaArgs, "--platform", platformArgs)

		patchedImage = []string{} // Clear the default patchedImage
		for _, p := range params.Platform {
			arch := multiplatform.PlatformToArch(p)
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
		return "", []string{}, fmt.Errorf("%s", errorMsg)
	}
	return vexPath, patchedImage, nil
}

// RunReportBased handles report-based patching with vulnerability scanning
func RunReportBased(ctx context.Context, cc *mcp.ServerSession, params types.ReportBasedPatchParams, reportPath string) (vexPath string, patchedImage []string, err error) {
	legacyParams := types.PatchParams{
		Image:    params.Image,
		Tag:      params.Tag,
		Push:     params.Push,
		Platform: params.Platform,
		Scan:     true, // Always true for report-based
	}
	return Run(ctx, cc, legacyParams, reportPath)
}

// RunPlatformSelective handles platform-selective patching
func RunPlatformSelective(ctx context.Context, cc *mcp.ServerSession, params types.PlatformSelectivePatchParams) (vexPath string, patchedImage []string, err error) {
	legacyParams := types.PatchParams{
		Image:    params.Image,
		Tag:      params.Tag,
		Push:     params.Push,
		Platform: params.Platform,
		Scan:     false,
	}
	return Run(ctx, cc, legacyParams, "")
}

// RunComprehensive handles comprehensive patching of all platforms
func RunComprehensive(ctx context.Context, cc *mcp.ServerSession, params types.ComprehensivePatchParams) (vexPath string, patchedImage []string, err error) {
	legacyParams := types.PatchParams{
		Image:    params.Image,
		Tag:      params.Tag,
		Push:     params.Push,
		Platform: []string{}, // Empty means all platforms
		Scan:     false,
	}
	return Run(ctx, cc, legacyParams, "")
}
