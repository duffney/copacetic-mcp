package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/duffney/copacetic-mcp/internal/types"
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
		args := trivyArgs
		args = append(args, "--image-src", "remote")
		args = append(args, "--platform", p)
		args = append(args, "-o", filepath.Join(reportPath, strings.ReplaceAll(p, "/", "-")+".json"))
		args = append(args, image)

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

// Scan performs vulnerability scanning and returns detailed scan results
func Scan(ctx context.Context, cc *mcp.ServerSession, params types.ScanParams) (*types.ScanResult, error) {
	reportPath, err := Run(ctx, cc, params.Image, params.Platform)
	if err != nil {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	// Count vulnerabilities in the report(s)
	vulnCount, err := countVulnerabilitiesInReport(reportPath)
	if err != nil {
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   fmt.Sprintf("Warning: Could not count vulnerabilities in report: %v", err),
			Level:  "warn",
			Logger: "trivy",
		})
		vulnCount = 0
	}

	platforms := params.Platform
	if len(platforms) == 0 {
		platforms = []string{"host platform"}
	}

	return &types.ScanResult{
		Image:         params.Image,
		ReportPath:    reportPath,
		VulnCount:     vulnCount,
		Platforms:     platforms,
		ScanCompleted: true,
	}, nil
}

// countVulnerabilitiesInReport counts total vulnerabilities across all report files
func countVulnerabilitiesInReport(reportPath string) (int, error) {
	// Read directory to find all JSON report files
	entries, err := os.ReadDir(reportPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read report directory: %w", err)
	}

	totalVulns := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			filePath := filepath.Join(reportPath, entry.Name())
			vulns, err := countVulnerabilitiesInFile(filePath)
			if err != nil {
				return 0, fmt.Errorf("failed to count vulnerabilities in %s: %w", filePath, err)
			}
			totalVulns += vulns
		}
	}

	return totalVulns, nil
}

// countVulnerabilitiesInFile counts vulnerabilities in a single JSON report file
func countVulnerabilitiesInFile(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read report file: %w", err)
	}

	var report struct {
		Results []struct {
			Vulnerabilities []interface{} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return 0, fmt.Errorf("failed to parse JSON report: %w", err)
	}

	totalVulns := 0
	for _, result := range report.Results {
		totalVulns += len(result.Vulnerabilities)
	}

	return totalVulns, nil
}
