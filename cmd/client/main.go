package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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

	params := &mcp.CallToolParams{
		Name: "patch",
		// Arguments: map[string]any{"image": "alpine:3.17", "push": false, "scan": true},
		// Report-Based Mulit-platforms
		Arguments: map[string]any{"image": "alpine:3.17", "push": false, "scan": true, "patchtag": "mcp-test", "platform": []string{"linux/amd64", "linux/arm64"}},
		// Arguments: map[string]any{"image": "ghcr.io/duffney/copacetic-test:latest", "push": false},
		// Arguments: map[string]any{"image": "alpine:3.17", "patchtag": "mcp", "push": false, "scan": true},
		// Arguments: map[string]any{"image": "alpine:3.17", "patchtag": "mcp"},
	}
	res, err := session.CallTool(ctx, params)
	if err != nil {
		log.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		// Print error content if available
		for _, c := range res.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				log.Fatalf("tool failed: %s", text.Text)
			}
		}
		log.Fatal("tool failed with unknown error")
	}
	for _, c := range res.Content {
		fmt.Println(c.(*mcp.TextContent).Text)
		// log.Print(c.(*mcp.TextContent).Text)
	}
}
