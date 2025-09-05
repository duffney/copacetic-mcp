FROM debian:12-slim
WORKDIR /app
ARG TARGETARCH
ARG TARGETOS

# Install runtime dependencies (include qemu for cross-arch emulation)
RUN apt-get update && \
    apt-get install -y tar ca-certificates gnupg curl jq qemu-user-static binfmt-support --no-install-recommends && \
    # Import Docker GPG key (adding keyring; actual docker packages are installed conditionally)
    install -m 0755 -d /etc/apt/keyrings && \
    curl --retry 5 -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=${TARGETARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get install -y docker-ce docker-ce-cli docker-buildx-plugin containerd.io --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Install Trivy (vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    trivy --version

# Install Copa (copacetic). Most releases publish amd64 binaries; only install on amd64.
RUN curl --retry 5 -fsSL -o copa.tar.gz https://github.com/project-copacetic/copacetic/releases/download/v0.11.1/copa_0.11.1_linux_${TARGETARCH}.tar.gz && \
    tar -zxvf copa.tar.gz && \
    mv copa /usr/local/bin/ && \
    rm -f copa.tar.gz

# Goreleaser builds the Go binaries first and provides them in the Docker build context.
# Make the binary name configurable so goreleaser can pass it in; default to the local name
ARG BINARY=./copacetic-mcp-server
COPY ${BINARY} /app/copacetic-mcp-server
ENTRYPOINT ["/app/copacetic-mcp-server"]
