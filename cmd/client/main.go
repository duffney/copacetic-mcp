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

	// Test version tool first
	testTool(ctx, session, "version", map[string]any{})

	// Test the new focused tools
	fmt.Println("\n=== Testing New Focused Patching Tools ===")

	// Test comprehensive patching (patches all platforms)
	testTool(ctx, session, "patch-comprehensive", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "comprehensive-test",
		"push":     false,
	})

	// Test platform-specific patching
	testTool(ctx, session, "patch-platforms", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "platform-test",
		"push":     false,
		"platform": []string{"linux/amd64"},
	})

	// Test vulnerability-based patching (with scanning)
	testTool(ctx, session, "patch-vulnerabilities", map[string]any{
		"image":    "alpine:3.17",
		"patchtag": "vuln-test",
		"push":     false,
		"platform": []string{"linux/amd64"},
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
