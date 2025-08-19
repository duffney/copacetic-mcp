package main

import (
	"context"
	"fmt"
	"log"
	// "os"
	"bufio"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-client", Version: "v1.0.0"}, nil)

	cmd := exec.Command("/home/jduffney/projects/mcp-go-sdk-examples/myserver")
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

	// call greet
	params := &mcp.CallToolParams{
		Name:      "copapatch",
		Arguments: map[string]any{"image": "alpine:3.17", "patchtag": "mcp"},
	}
	res, err := session.CallTool(ctx, params)
	if err != nil {
		log.Fatal("CallTool failed: %v", err)
	}
	if res.IsError {
		log.Fatal("tool failed")
	}
	for _, c := range res.Content {
		fmt.Println(c.(*mcp.TextContent).Text)
		// log.Print(c.(*mcp.TextContent).Text)
	}
}
