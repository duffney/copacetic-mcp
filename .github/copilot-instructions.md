# Copacetic MCP Server

## Project Overview
Copacetic MCP is a Go application that provides a Model Context Protocol (MCP) server for automated container image patching using Copacetic and Trivy. It exposes container patching capabilities through the MCP protocol, allowing AI agents and tools to patch container image vulnerabilities programmatically.

**Main commands**: MCP tools `version` and `patch`
**Module**: `github.com/duffney/copacetic-mcp`

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Folder Structure
- `main.go`: Main MCP server entry point
- `cmd/client/main.go`: Test client for validating MCP server functionality  
- `internal/mcp/`: MCP server setup, tool registration, and protocol handlers
- `internal/copa/`: Copacetic command execution and container patching logic
- `internal/trivy/`: Trivy vulnerability scanning integration
- `internal/types/`: Shared type definitions and execution modes
- `internal/util/`: Utility functions for multiplatform support
- `.goreleaser.yml`: GoReleaser configuration for cross-platform releases
- `.github/workflows/`: CI/CD automation (build.yml, release.yml)
- `Makefile`: Development tasks and build automation

## Libraries and Frameworks
- **MCP Protocol**: `github.com/modelcontextprotocol/go-sdk/mcp` for Model Context Protocol server implementation
- **Container Registry**: `github.com/google/go-containerregistry` for container image operations
- **Docker Integration**: `github.com/docker/docker` for container runtime operations
- **VEX Support**: `github.com/openvex/go-vex` for vulnerability exchange document generation
- **External Tools**: Copacetic (copa) for patching, Trivy for vulnerability scanning
- **Cross-platform Builds**: GoReleaser for automated multi-platform binary releases

## Coding Standards
- Follow Go best practices and standard formatting (`make fmt`)
- Use `go vet` for static analysis validation (`make vet`)
- Implement comprehensive error handling with wrapped errors using `fmt.Errorf`
- Write tests for new functionality with proper Docker test environment detection
- Use structured logging for debugging and operational visibility
- Follow MCP protocol specifications for tool definitions and responses
- Handle multiplatform scenarios appropriately for container operations

## Key Architecture Concepts
- **MCP Server Architecture**: Provides `version` and `patch` tools through stdin/stdout MCP protocol
- **Execution Modes**: 
  - `comprehensive`: Patches all available updates without vulnerability report
  - `report-based`: Patches only vulnerabilities identified through Trivy scanning
- **Multiplatform Support**: Handles container images across multiple architectures (amd64, arm64, etc.)
- **External Tool Integration**: Orchestrates Copacetic and Trivy through command execution
- **VEX Generation**: Creates Vulnerability Exchange (VEX) documents for patching results
- **Cross-platform Binary Distribution**: Builds native binaries for Linux, macOS, and Windows

## Supported Container Scenarios
- **Single-arch images**: Direct patching of images for specific platform
- **Multi-arch images**: Platform-specific patching while preserving other architectures  
- **Registry Operations**: Pull, patch, and optionally push patched images
- **Tag Management**: Automatic tagging of patched images with `-patched` suffix
- **Vulnerability Reporting**: Integration with Trivy for security scanning

## Key Functions and Components
- `NewServer()`: Creates MCP server instance with registered tools
- `Run()`: Starts MCP server with stdio transport
- `Patch()`: Main patching tool that orchestrates vulnerability scanning and image patching
- `Version()`: Returns Copacetic version information
- `copa.Run()`: Executes Copacetic patching with proper argument construction
- `trivy.Scan()`: Performs vulnerability scanning using Trivy
- `DetermineExecutionMode()`: Selects appropriate patching strategy based on parameters

## Working Effectively

### Prerequisites and Installation
- Go 1.20 or later (tested with Go 1.24.6)
- Docker (for container operations and some tests)
- [Copacetic](https://github.com/project-copacetic/copacetic) v0.8.0+ for container patching
- [Trivy](https://github.com/aquasecurity/trivy) v0.65.0+ for vulnerability scanning
- [GoReleaser](https://goreleaser.com/) v2.5.0+ for releases

### Install Required Dependencies

Install Copacetic:
```bash
wget -O copa.tar.gz https://github.com/project-copacetic/copacetic/releases/download/v0.8.0/copa_0.8.0_linux_amd64.tar.gz
tar -xzf copa.tar.gz
sudo cp copa /usr/local/bin/
copa --version  # Should show: copa version 0.8.0
```

Install Trivy:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
trivy --version  # Should show: Version: 0.65.0
```

Install GoReleaser (for releases):
```bash
curl -sLO https://github.com/goreleaser/goreleaser/releases/download/v2.5.0/goreleaser_Linux_x86_64.tar.gz
tar -xzf goreleaser_Linux_x86_64.tar.gz
sudo cp goreleaser /usr/local/bin/
goreleaser --version  # Should show version 2.5.0
```

### Build and Test Commands

**NEVER CANCEL ANY BUILD OR TEST COMMAND** - All commands may take longer than expected. Always use adequate timeouts.

Build the project:
```bash
make build  # Takes ~40 seconds. NEVER CANCEL. Set timeout to 120+ seconds.
```

Run tests:
```bash
make test  # Takes ~8 seconds. Docker tests are automatically skipped in CI.
```

Format and validate code:
```bash
make fmt    # Takes ~0.2 seconds
make vet    # Takes ~5 seconds
```

Cross-compile for all platforms:
```bash
make cross-compile  # Takes ~1 minute 45 seconds. NEVER CANCEL. Set timeout to 240+ seconds.
```

Build release artifacts:
```bash
make release-snapshot  # Takes ~2 minutes 41 seconds. NEVER CANCEL. Set timeout to 300+ seconds.
```

### Run the Application

Start the MCP server (interactive mode):
```bash
./bin/copacetic-mcp-server
# Server waits for MCP protocol messages on stdin/stdout
# Use Ctrl+C to stop
```

Run the test client (requires server dependencies):
```bash
./bin/copacetic-mcp-client
# Connects to server and tests the 'patch' tool with alpine:3.17
```

## Validation

### Always Run These Steps After Making Changes:

1. **Build validation** - Build succeeds without errors:
   ```bash
   make build  # Set timeout to 120+ seconds, NEVER CANCEL
   ```

2. **Test validation** - All tests pass:
   ```bash
   make test  # Docker tests skip automatically in CI environments
   ```

3. **Code quality validation** - Required for CI to pass:
   ```bash
   make fmt vet  # Both commands must complete successfully
   ```

4. **MCP server functionality validation** - Test server-client communication:
   ```bash
   # Create test script to validate version tool:
   cat > test_mcp.go << 'EOF'
   package main
   import (
       "context"
       "fmt"
       "log"
       "os/exec"
       "github.com/modelcontextprotocol/go-sdk/mcp"
   )
   func main() {
       ctx := context.Background()
       client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
       cmd := exec.Command("./bin/copacetic-mcp-server")
       transport := mcp.NewCommandTransport(cmd)
       session, err := client.Connect(ctx, transport)
       if err != nil { log.Fatal(err) }
       defer session.Close()
       params := &mcp.CallToolParams{Name: "version", Arguments: map[string]any{}}
       res, err := session.CallTool(ctx, params)
       if err != nil { log.Fatalf("CallTool failed: %v", err) }
       if res.IsError { log.Fatal("version tool failed") }
       for _, c := range res.Content {
           fmt.Printf("Success: %s\n", c.(*mcp.TextContent).Text)
       }
   }
   EOF
   go run test_mcp.go  # Should output: Success: copa version 0.8.0
   rm test_mcp.go
   ```

### Cross-Platform Validation

For release builds, validate cross-compilation works:
```bash
make cross-compile  # Set timeout to 240+ seconds, NEVER CANCEL
ls -la bin/  # Should show binaries for linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64.exe
```

## Important Build and Timing Information

- **Build time**: ~40 seconds (first time with dependencies)
- **Test time**: ~8 seconds (Docker tests automatically skip in CI)
- **Cross-compile time**: ~1 minute 45 seconds
- **Release build time**: ~2 minutes 41 seconds
- **Format/vet time**: <5 seconds combined

**CRITICAL**: NEVER CANCEL long-running commands. Builds and cross-compilation can take several minutes, especially on slower systems. Always set timeouts to at least double the expected time.

## Common Tasks and Troubleshooting

### MCP Server Architecture
The server provides two MCP tools:
- `version`: Returns copa version information
- `patch`: Patches container images using Copacetic

### Dependencies Not Available
If copa or trivy are not installed:
- Tests will still pass (external tool tests are conditional)
- MCP server will fail when tools are called
- Always install dependencies using the exact commands above

### Docker Tests Skipped
Docker tests automatically skip in CI environments (`CI` or `GITHUB_ACTIONS` env vars set). This is expected behavior.

### Build Artifacts
- Binaries: `bin/copacetic-mcp-server`, `bin/copacetic-mcp-client`
- Cross-compiled: `bin/copacetic-mcp-server-{os}-{arch}[.exe]`
- Release artifacts: `dist/` directory (excluded from git)

### Key Project Structure
```
copacetic-mcp/
├── main.go                     # Main MCP server entry point
├── cmd/client/main.go         # Test client for MCP server validation
├── internal/
│   ├── mcp/                   # MCP server handlers, tool registration, protocol implementation
│   ├── copa/                  # Copacetic command execution and container patching orchestration
│   ├── trivy/                 # Trivy vulnerability scanning integration
│   ├── types/                 # Shared type definitions, execution modes, and parameters
│   └── util/                  # Utility functions for multiplatform and cross-platform support
├── .goreleaser.yml            # GoReleaser configuration for automated releases
├── .github/workflows/         # GitHub Actions CI/CD automation
│   ├── build.yml             # Continuous integration: build, test, lint on every push/PR
│   └── release.yml           # Automated releases with cross-platform binaries on tags
└── Makefile                   # Development tasks: build, test, format, cross-compile, release
```

## CI/CD Integration

- GitHub Actions automatically builds and tests on push/PR
- Release process uses GoReleaser for cross-platform binaries
- Docker tests are automatically skipped in CI environments
- All validation steps (fmt, vet, test, build) must pass for CI success