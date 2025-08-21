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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"
)

/*
	TODO: Patch all local images and overwrite current tag
	TODO: Scan tool, return vulns wit sev.
	TODO: Run mcp server from a container to avoid having to install/config tools
	TODO: Support multiplatform **
*/

type Ver struct {
	Version string `json:"version" jsonschema:"the version of the copa cli"`
}

type PatchParams struct {
	Image string `json:"image" jsonschema:"the image reference of the container being patched"`
	Tag   string `json:"patchtag" jsonschema:"the new tag for the patched image"`
	Push  bool   `json:"push" jsonschema:"push patched image to destination registry"`
	// Scan      bool     `json:"scan" jsonschema:"scan container image to generate vulnerability report using trivy"`
	// Platforms []string `json:"platforms" jsonschema:"Target platform(s) for multi-arch images when no report directory is provided (e.g., linux/amd64,linux/arm64). Valid platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6. If platform flag is used, only specified platforms are patched and the rest are preserved. If not specified, all platforms present in the image are patched"`
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
	var tag, repository string
	ref, err := name.ParseReference(params.Arguments.Image)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: support digests
	if tagged, ok := ref.(name.Tag); ok {
		tag = tagged.TagStr()
		repository = tagged.Repository.RepositoryStr()
		repository = strings.TrimPrefix(repository, "library/")
	}

	tmpDir := os.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")

	trivyArgs := []string{
		"image",
		"--vuln-type", "os",
		"--ignore-unfixed",
		"-f", "json",
		"-o", reportPath,
	}
	args := append(trivyArgs, params.Arguments.Image)

	trivyCmd := exec.Command("trivy", args...)
	var stderrTrivy strings.Builder
	trivyCmd.Stderr = &stderrTrivy

	cc.Log(ctx, &mcp.LoggingMessageParams{
		Data:   "executing: " + strings.Join(append([]string{"trivy "}, trivyArgs...), " "),
		Level:  "debug",
		Logger: "copapatch",
	})

	err = trivyCmd.Run()
	if err != nil {
		exitCode := ""
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
		}
		errorMsg := fmt.Sprintf("trivy command failed%s: %v|n%s", exitCode, err, stderrTrivy.String())
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: errorMsg}},
		}, fmt.Errorf(errorMsg)
	}

	vexPath := filepath.Join(tmpDir, "vex.json")
	copaArgs := []string{
		"patch",
		"--report", reportPath,
		"--image", params.Arguments.Image,
		"--output", vexPath,
	}

	if params.Arguments.Tag != "" {
		copaArgs = append(copaArgs, "--tag", params.Arguments.Tag)
	} else {
		params.Arguments.Tag = tag + "-patched"
	}

	if params.Arguments.Push {
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
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: errorMsg}},
		}, fmt.Errorf(errorMsg)
	}

	vexData, err := os.ReadFile(vexPath)
	if err != nil {
		log.Fatal(err)
	}

	var doc vex.VEX

	if err := json.Unmarshal(vexData, &doc); err != nil {
		log.Fatal(err)
	}

	var fixedCount, subcomponentCount int

	for _, stmt := range doc.Statements {
		if stmt.Status == vex.StatusFixed {
			fixedCount++
			for _, product := range stmt.Products {
				subcomponentCount += len(product.Subcomponents)
			}
		}
	}

	patchedImage := repository + ":" + params.Arguments.Tag

	text := []string{}
	text = append(text, "successfully patched image: "+params.Arguments.Image)
	text = append(text, fmt.Sprintf("vulns fixed: %d, packages updated: %d", fixedCount, subcomponentCount))
	text = append(text, "new patched image: "+patchedImage)

	err = os.Remove(vexPath)
	if err != nil {
		log.Fatalf("error deleting file: %v", vexPath)
	}

	err = os.Remove(reportPath)
	if err != nil {
		log.Fatalf("error deleting file: %v", reportPath)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(text, "\n")}},
	}, nil
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
