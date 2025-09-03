package trivy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	multiplatform "github.com/duffney/copacetic-mcp/internal/util"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Run(ctx context.Context, cc *mcp.ServerSession, image string, platform []string) (reportPath string, err error) {
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

	if len(platform) == 0 {
		trivyArgs = append(trivyArgs, "-o", filepath.Join(reportPath, "report.json"))
		trivyArgs = append(trivyArgs, image)
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
			errorMsg := fmt.Sprintf("trivy command failed%s: %v\n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf("%s", errorMsg)
		}

		return reportPath, nil
	}

	for _, p := range platform {
		// Use the utility function to resolve platform-specific digest
		imageWithDigest, err := multiplatform.ResolvePlatformSpecificDigest(image, p)
		if err != nil {
			cc.Log(ctx, &mcp.LoggingMessageParams{
				Data:   fmt.Sprintf("Warning: Could not resolve platform-specific digest for %s on %s: %v, using original image", image, p, err),
				Level:  "warn",
				Logger: "copapatch",
			})
			imageWithDigest = image
		} else {
			cc.Log(ctx, &mcp.LoggingMessageParams{
				Data:   fmt.Sprintf("Resolved %s for platform %s to digest: %s", image, p, imageWithDigest),
				Level:  "debug",
				Logger: "copapatch",
			})
		}

		args := trivyArgs
		args = append(args, "--platform", p)
		args = append(args, "-o", filepath.Join(reportPath, strings.ReplaceAll(p, "/", "-")+".json"))
		args = append(args, imageWithDigest)

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
			errorMsg := fmt.Sprintf("trivy command failed%s: %v\n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf("%s", errorMsg)
		}
	}

	return reportPath, nil
}
