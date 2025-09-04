package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testTool(ctx context.Context, session *mcp.ClientSession, toolName string, args map[string]any) (string, error) {
	fmt.Printf("\n=== Testing %s tool ===\n", toolName)

	params := &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	}

	res, err := session.CallTool(ctx, params)
	if err != nil {
		return "", fmt.Errorf("CallTool failed for %s: %v", toolName, err)
	}

	if res.IsError {
		var errMsg string
		for _, c := range res.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				errMsg += text.Text
			}
		}
		return "", fmt.Errorf("%s tool failed: %s", toolName, errMsg)
	}

	var result string
	for _, c := range res.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			result = text.Text
			fmt.Printf("Result: %s\n", result)
		}
	}
	return result, nil
}

func extractReportPath(scanResult string) string {
	// Extract report directory path from scan result
	re := regexp.MustCompile(`Report directory: (\S+)`)
	matches := re.FindStringSubmatch(scanResult)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func main() {
	ctx := context.Background()

	client := mcp.NewClient(
		&mcp.Implementation{Name: "workflow-demo", Version: "v1.0.0"},
		&mcp.ClientOptions{
			LoggingMessageHandler: func(ctx context.Context, session *mcp.ClientSession, params *mcp.LoggingMessageParams) {
				fmt.Printf("[server log][%s] %v\n", params.Level, params.Data)
			},
		},
	)

	cmd := exec.Command("/home/jduffney/github/copacetic-mcp/bin/copacetic-mcp-server")
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to get stderr pipe: %v", err)
	}
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[server stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading server stderr: %v", err)
		}
	}()

	transport := mcp.NewCommandTransport(cmd)
	session, err := client.Connect(ctx, transport)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	session.SetLevel(ctx, &mcp.SetLevelParams{Level: "debug"})

	fmt.Println("=== Complete Vulnerability Scanning and Patching Workflow ===")

	// Step 1: Scan the container for vulnerabilities
	fmt.Println("\n--- Step 1: Scan Container for Vulnerabilities ---")
	scanResult, err := testTool(ctx, session, "scan-container", map[string]any{
		"image":    "alpine:3.17",
		"platform": []string{"linux/amd64"},
	})
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Step 2: Extract the report path from scan results
	reportPath := extractReportPath(scanResult)
	if reportPath == "" {
		log.Fatal("Could not extract report path from scan result")
	}
	fmt.Printf("\n✓ Report generated at: %s\n", reportPath)

	// Step 3: Patch vulnerabilities using the generated report
	fmt.Println("\n--- Step 2: Patch Vulnerabilities Using Report ---")
	_, err = testTool(ctx, session, "patch-vulnerabilities", map[string]any{
		"image":      "alpine:3.17",
		"patchtag":   "alpine-patched-demo",
		"push":       false,
		"reportPath": reportPath,
	})
	if err != nil {
		log.Fatalf("Patching failed: %v", err)
	}

	fmt.Println("\n✅ Complete workflow successful!")
	fmt.Println("Summary:")
	fmt.Println("1. ✓ Scanned alpine:3.17 for vulnerabilities")
	fmt.Println("2. ✓ Generated vulnerability report")
	fmt.Println("3. ✓ Patched vulnerabilities using the report")
	fmt.Println("4. ✓ Created patched image: alpine:alpine-patched-demo")
}
