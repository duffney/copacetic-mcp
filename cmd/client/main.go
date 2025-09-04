package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testTool(ctx context.Context, session *mcp.ClientSession, toolName string, args map[string]any) {
	fmt.Printf("\n=== Testing %s tool ===\n", toolName)

	params := &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	}

	res, err := session.CallTool(ctx, params)
	if err != nil {
		log.Printf("CallTool failed for %s: %v", toolName, err)
		return
	}

	if res.IsError {
		for _, c := range res.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				log.Printf("%s tool failed: %s", toolName, text.Text)
			}
		}
		return
	}

	for _, c := range res.Content {
		fmt.Printf("Result: %s\n", c.(*mcp.TextContent).Text)
	}
}

func main() {
	ctx := context.Background()

	client := mcp.NewClient(
		&mcp.Implementation{Name: "mcp-client", Version: "v1.0.0"},
		&mcp.ClientOptions{
			LoggingMessageHandler: func(ctx context.Context, session *mcp.ClientSession, params *mcp.LoggingMessageParams) {
				fmt.Printf("[server log][%s] %v\n", params.Level, params.Data)
			},
		},
	)

	cmd := exec.Command("/home/jduffney/github/copacetic-mcp/bin/copacetic-mcp-server")
	// Capture server's stderr for logging
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to get stderr pipe: %v", err)
	}
	// Start goroutine to read and log stderr
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

	// Enable receiving log messages from the server
	session.SetLevel(ctx, &mcp.SetLevelParams{Level: "debug"})

	// List all available tools
	fmt.Println("\n=== Available MCP Tools ===")
	listRes, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		log.Printf("Failed to list tools: %v", err)
	} else {
		for _, tool := range listRes.Tools {
			fmt.Printf("- %s: %s\n", tool.Name, tool.Description)
		}
	}

	// Test version tool first
	testTool(ctx, session, "version", map[string]any{})

	// Test the new focused tools
	fmt.Println("\n=== Testing New Focused Patching Tools ===")

	// Test the new scan-container tool first
	fmt.Println("\n--- Testing scan-container tool ---")
	testTool(ctx, session, "scan-container", map[string]any{
		"image":    "alpine:3.17",
		"platform": []string{"linux/amd64"},
	})

	// Test comprehensive patching (patches all platforms)
	fmt.Println("\n--- Testing patch-comprehensive tool ---")
	testTool(ctx, session, "patch-comprehensive", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "comprehensive-test",
		"push":     false,
	})

	// Test platform-specific patching
	fmt.Println("\n--- Testing patch-platforms tool ---")
	testTool(ctx, session, "patch-platforms", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "platform-test",
		"push":     false,
		"platform": []string{"linux/amd64"},
	})

	// Test vulnerability-based patching (should fail without report path)
	fmt.Println("\n--- Testing patch-vulnerabilities tool (should fail without report) ---")
	testTool(ctx, session, "patch-vulnerabilities", map[string]any{
		"image":      "alpine:3.17",
		"patchtag":   "vuln-test",
		"push":       false,
		"reportPath": "", // Empty report path should cause failure
	})

	// Test vulnerability-based patching with nonexistent report path
	fmt.Println("\n--- Testing patch-vulnerabilities tool (should fail with invalid report) ---")
	testTool(ctx, session, "patch-vulnerabilities", map[string]any{
		"image":      "alpine:3.17",
		"patchtag":   "vuln-test-2",
		"push":       false,
		"reportPath": "/tmp/nonexistent-report-dir",
	})

	// Test the legacy patch tool for comparison
	fmt.Println("\n=== Testing Legacy Patch Tool ===")
	testTool(ctx, session, "patch", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "legacy-test",
		"push":     false,
		"scan":     false,
	})
}
