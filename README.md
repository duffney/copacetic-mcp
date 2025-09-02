# copacetic-mcp

A Model Context Protocol (MCP) server for automated container patching using [Copacetic](https://github.com/project-copacetic/copacetic).

## Features

- **Container Patching**: Patch container images for security vulnerabilities using Copacetic
- **Vulnerability Scanning**: Scan images with Trivy to identify vulnerabilities
- **Multi-platform Support**: Support for ARM64 and AMD64 architectures
- **VEX Document Generation**: Generate VEX (Vulnerability Exploitability eXchange) documents
- **MCP Integration**: Easy integration with MCP-compatible tools and LLMs

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/duffney/copacetic-mcp/releases).

#### Linux (AMD64)

```bash
curl -L https://github.com/duffney/copacetic-mcp/releases/latest/download/copacetic-mcp_Linux_x86_64.tar.gz | tar xz
./copacetic-mcp-server
```

#### Linux (ARM64)

```bash
curl -L https://github.com/duffney/copacetic-mcp/releases/latest/download/copacetic-mcp_Linux_arm64.tar.gz | tar xz
./copacetic-mcp-server
```

#### macOS (AMD64)

```bash
curl -L https://github.com/duffney/copacetic-mcp/releases/latest/download/copacetic-mcp_Darwin_x86_64.tar.gz | tar xz
./copacetic-mcp-server
```

#### macOS (ARM64/Apple Silicon)

```bash
curl -L https://github.com/duffney/copacetic-mcp/releases/latest/download/copacetic-mcp_Darwin_arm64.tar.gz | tar xz
./copacetic-mcp-server
```

### Build from Source

```bash
git clone https://github.com/duffney/copacetic-mcp.git
cd copacetic-mcp
make build
```

## Development

### Prerequisites

- Go 1.20 or later
- [Copacetic](https://github.com/project-copacetic/copacetic) installed
- [Trivy](https://github.com/aquasecurity/trivy) installed

### Building

```bash
# Build both server and client
make build

# Build only the server
make build-server

# Build only the client
make build-client

# Cross-compile for all platforms
make cross-compile
```

### Testing

```bash
# Run all tests
make test

# Format code
make fmt

# Run vet
make vet
```

### Release Process

This project uses [GoReleaser](https://goreleaser.com/) for automated releases.

#### Creating a Release

1. **Create and push a tag:**

   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically:**
   - Run tests
   - Build cross-platform binaries
   - Create release archives
   - Generate checksums
   - Create a GitHub release
   - Upload artifacts

#### Supported Platforms

The automated release process builds for:

- **Linux**: AMD64, ARM64
- **macOS**: AMD64, ARM64 (Apple Silicon)
- **Windows**: AMD64

#### Manual Release (for testing)

```bash
# Create a snapshot release (no tags required)
make release-snapshot

# Or use GoReleaser directly
goreleaser release --snapshot --clean
```

### Project Structure

```
copacetic-mcp/
├── main.go                     # Main MCP server entry point
├── cmd/client/main.go         # Test client
├── internal/
│   ├── mcp/                   # MCP server handlers and setup
│   ├── copa/                  # Copacetic command execution
│   ├── trivy/                 # Trivy vulnerability scanning
│   ├── types/                 # Shared type definitions
│   └── util/                  # Utility functions (multiplatform, etc.)
├── .goreleaser.yml            # GoReleaser configuration
├── .github/workflows/         # GitHub Actions workflows
│   ├── build.yml             # Build and test on every push/PR
│   └── release.yml           # Automated releases on tags
└── Makefile                   # Development tasks
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run `make test fmt vet`
6. Submit a pull request

## License

[Add your license here]
