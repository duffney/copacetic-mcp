#!/bin/bash

echo "Testing MCP workflow guidance..."

# Create a simple test to verify the tools are working
cat > test_mcp_tools.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-workflow-client",
		Version: "v1.0.0",
	}, nil)

	cmd := exec.Command("./bin/copacetic-mcp-server")
	transport := mcp.NewCommandTransport(cmd)

	session, err := client.Connect(ctx, transport)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	// Test list tools to see available tools
	tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		log.Fatalf("ListTools failed: %v", err)
	}

	fmt.Printf("Available tools: %d\n", len(tools.Tools))
	for _, tool := range tools.Tools {
		fmt.Printf("- %s: %s\n", tool.Name, tool.Description)
	}

	// Test workflow-guide tool
	fmt.Println("\n=== Testing workflow-guide tool ===")
	params := &mcp.CallToolParams{
		Name:      "workflow-guide",
		Arguments: map[string]any{},
	}

	res, err := session.CallTool(ctx, params)
	if err != nil {
		log.Fatalf("workflow-guide tool failed: %v", err)
	}

	if res.IsError {
		log.Fatalf("workflow-guide tool returned error: %v", res.Content)
	}

	for _, content := range res.Content {
		if textContent, ok := content.(*mcp.TextContent); ok {
			fmt.Println(textContent.Text)
		}
	}
}
EOF

go run test_mcp_tools.go
rm test_mcp_tools.go
