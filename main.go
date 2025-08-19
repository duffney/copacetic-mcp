package main

import (
	"context"
	"encoding/json"
	"fmt"

	// "errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openvex/go-vex/pkg/vex"
)

/*
	TODO: Return patch report
	TODO: Scan tool, return vulns wit sev.
	TODO: Run mcp server from a container to avoid having to install/config tools
*/

type Copa struct {
	Version string `json:"version" jsonschema:"the version of the copa cli"`
}

type CopaPatchParams struct {
	Image    string `json:"image" jsonschema:"the image reference of the container being patched"`
	PatchTag string `json:"patchtag" jsonschema:"the new tag for the patched image"`
}

func CopaHelp(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[Copa]) (*mcp.CallToolResultFor[any], error) {
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

func CopaPatch(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[CopaPatchParams]) (*mcp.CallToolResultFor[any], error) {
	tmpDir := os.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")

	baseArgs := []string{
		"image",
		"--vuln-type", "os",
		"--ignore-unfixed",
		"-f", "json",
		"-o", reportPath,
	}
	args := append(baseArgs, params.Arguments.Image)

	cmd := exec.Command("trivy", args...)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	vexPath := filepath.Join(tmpDir, "vex.json")
	copaArgs := []string{
		"patch",
		"--report", reportPath,
		"--image", params.Arguments.Image,
		"--tag", params.Arguments.PatchTag,
		"--output", vexPath,
	}

	log.Printf("Executing: %s", strings.Join(append([]string{"copa"}, copaArgs...), " "))

	// TODO: Capture error message details from stdout
	// TODO: Support --push
	copaCmd := exec.Command("copa", copaArgs...)
	err = copaCmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			log.Printf("patching was not successful. Copa exited with code %d: %v\n", exitError.ExitCode(), err)
		} else {
			log.Printf("pacthing was not successful: %v\n", err)
		}
		log.Fatal(err)
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

	imageName := strings.SplitN(params.Arguments.Image, ":", 2)[0]
	patchedImage := imageName + ":" + params.Arguments.PatchTag

	text := []string{}
	text = append(text, "successfully patched image: "+params.Arguments.Image)
	text = append(text, fmt.Sprintf("vulns fixed: %d, packages updated: %d", fixedCount, subcomponentCount))
	text = append(text, "new patched image: "+patchedImage)

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(text, "\n")}},
	}, nil
}

func main() {
	// Create a server with a single tool.
	server := mcp.NewServer(&mcp.Implementation{Name: "", Version: "v1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "copahelp", Description: "Copacetic automated container pactching"}, CopaHelp)
	mcp.AddTool(server, &mcp.Tool{Name: "copapatch", Description: "Pacth container image with copacetic"}, CopaPatch)
	// Run the server over stdin/stdout, until the client disconnects
	if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
		log.Fatal(err)
	}
}
