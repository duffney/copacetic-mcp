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
			arch := multiplatform.PlatformToArch(p)
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
		return "", []string{}, fmt.Errorf("%s", errorMsg)
	}
	return vexPath, patchedImage, nil
}
