package trivy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Run(ctx context.Context, cc *mcp.ServerSession, image string, platform []string) (reportPath string, err error) {
	reportPath, err = os.MkdirTemp(os.TempDir(), "reports-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary report directory: %w", err)
	}
	trivyArgs := []string{
		"image",
		"--vuln-type", "os",
		"--ignore-unfixed",
		"-f", "json",
	}

	if len(platform) == 0 {
		trivyArgs = append(trivyArgs, "-o", filepath.Join(reportPath, "report.json"))
		trivyArgs = append(trivyArgs, image)
		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   "executing: " + strings.Join(append([]string{"trivy "}, trivyArgs...), " "),
			Level:  "debug",
			Logger: "copapatch",
		})

		trivyCmd := exec.Command("trivy", trivyArgs...)
		var stderrTrivy strings.Builder
		trivyCmd.Stderr = &stderrTrivy

		err = trivyCmd.Run()
		if err != nil {
			exitCode := ""
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
			}
			errorMsg := fmt.Sprintf("trivy command failed%s: %v\n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf("%s", errorMsg)
		}

		return reportPath, nil
	}

	for _, p := range platform {
		var repository, imageWithDigest string
		ref, err := name.ParseReference(image)
		if err != nil {
			return "", fmt.Errorf("failed to parse image reference %s: %w", image, err)
		}

		if tagged, ok := ref.(name.Tag); ok {
			repository = tagged.RepositoryStr()
			repository = strings.TrimPrefix(repository, "library/")

			// Parse platform (e.g., "linux/amd64" -> "linux", "amd64")
			platformParts := strings.Split(p, "/")
			if len(platformParts) != 2 {
				cc.Log(ctx, &mcp.LoggingMessageParams{
					Data:   fmt.Sprintf("Warning: Invalid platform format %s, using original image", p),
					Level:  "warn",
					Logger: "copapatch",
				})
				imageWithDigest = image
			} else {
				// Create platform spec
				platformSpec := v1.Platform{
					OS:           platformParts[0],
					Architecture: platformParts[1],
				}

				// Get the descriptor first
				desc, err := remote.Get(ref)
				if err != nil {
					cc.Log(ctx, &mcp.LoggingMessageParams{
						Data:   fmt.Sprintf("Warning: Could not get manifest for %s: %v, using original image", image, err),
						Level:  "warn",
						Logger: "copapatch",
					})
					imageWithDigest = image
				} else {
					// Try to get as manifest list/index first
					idx, err := desc.ImageIndex()
					if err != nil {
						// Not a manifest list, try as single image
						_, err := desc.Image()
						if err != nil {
							cc.Log(ctx, &mcp.LoggingMessageParams{
								Data:   fmt.Sprintf("Warning: Could not parse manifest for %s: %v, using original image", image, err),
								Level:  "warn",
								Logger: "copapatch",
							})
							imageWithDigest = image
						} else {
							// Single platform image, use its digest
							digest := desc.Digest.String()
							imageWithDigest = fmt.Sprintf("%s@%s", repository, digest)
							cc.Log(ctx, &mcp.LoggingMessageParams{
								Data:   fmt.Sprintf("Single platform image %s resolved to digest: %s", image, imageWithDigest),
								Level:  "debug",
								Logger: "copapatch",
							})
						}
					} else {
						// It's a manifest list/index - find the platform-specific manifest
						manifest, err := idx.IndexManifest()
						if err != nil {
							cc.Log(ctx, &mcp.LoggingMessageParams{
								Data:   fmt.Sprintf("Warning: Could not get index manifest for %s: %v, using original image", image, err),
								Level:  "warn",
								Logger: "copapatch",
							})
							imageWithDigest = image
						} else {
							var platformDigest string
							for _, m := range manifest.Manifests {
								if m.Platform != nil &&
									m.Platform.OS == platformSpec.OS &&
									m.Platform.Architecture == platformSpec.Architecture {
									platformDigest = m.Digest.String()
									break
								}
							}

							if platformDigest != "" {
								imageWithDigest = fmt.Sprintf("%s@%s", repository, platformDigest)
								cc.Log(ctx, &mcp.LoggingMessageParams{
									Data:   fmt.Sprintf("Resolved %s for platform %s to digest: %s", image, p, imageWithDigest),
									Level:  "debug",
									Logger: "copapatch",
								})
							} else {
								cc.Log(ctx, &mcp.LoggingMessageParams{
									Data:   fmt.Sprintf("Warning: Could not find platform %s in manifest list, using original image", p),
									Level:  "warn",
									Logger: "copapatch",
								})
								imageWithDigest = image
							}
						}
					}
				}
			}
		}

		args := trivyArgs
		args = append(args, "--platform", p)
		args = append(args, "-o", filepath.Join(reportPath, strings.ReplaceAll(p, "/", "-")+".json"))
		args = append(args, imageWithDigest)

		cc.Log(ctx, &mcp.LoggingMessageParams{
			Data:   "executing: " + strings.Join(append([]string{"trivy "}, args...), " "),
			Level:  "debug",
			Logger: "copapatch",
		})

		trivyCmd := exec.Command("trivy", args...)
		var stderrTrivy strings.Builder
		trivyCmd.Stderr = &stderrTrivy

		err = trivyCmd.Run()
		if err != nil {
			exitCode := ""
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = fmt.Sprintf(" (exit code %d)", exitError.ExitCode())
			}
			errorMsg := fmt.Sprintf("trivy command failed%s: %v\n%s", exitCode, err, stderrTrivy.String())
			return "", fmt.Errorf("%s", errorMsg)
		}
	}

	return reportPath, nil
}
