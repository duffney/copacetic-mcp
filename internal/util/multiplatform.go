// Package multiplatform provides utilities to detect if Docker images support multiple platforms.
package multiplatform

import (
	"context"
	"fmt"
	"runtime"

	"github.com/docker/docker/client"
)

// CopaSupportedPlatforms lists all platforms that Copa can patch
// Based on Copa documentation: https://project-copacetic.github.io/copacetic/website/multiplatform-patching
var CopaSupportedPlatforms = []string{
	"linux/amd64",
	"linux/arm64",
	"linux/arm/v7",
	"linux/arm/v6",
	"linux/386",
	"linux/ppc64le",
	"linux/s390x",
	"linux/riscv64",
}

// ImageInfo contains information about an image's platform support and availability
type ImageInfo struct {
	IsMultiPlatform bool
	IsLocal         bool
	Platform        []string // Available platforms (e.g., ["linux/amd64", "linux/arm64"])
}

// GetImageInfo checks if the given image reference supports multiple platforms
// and whether it's available locally or requires remote access.
func GetImageInfo(ctx context.Context, imageRef string) (*ImageInfo, error) {
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	// Try local image first
	if info, err := checkLocalImageInfo(ctx, cli, imageRef); err == nil {
		info.IsLocal = true
		return info, nil
	}

	// Fall back to remote image
	info, err := checkRemoteImageInfo(ctx, cli, imageRef)
	if err != nil {
		return nil, err
	}
	info.IsLocal = false
	return info, nil
}

// IsMultiPlatform checks if the given image reference supports multiple platforms.
// It returns true if the image is a manifest list (multiplatform), false otherwise.
// This function maintains backward compatibility.
func IsMultiPlatform(ctx context.Context, imageRef string) (bool, error) {
	info, err := GetImageInfo(ctx, imageRef)
	if err != nil {
		return false, err
	}
	return info.IsMultiPlatform, nil
}

// checkLocalImageInfo checks if a local image is multiplatform and gathers info
func checkLocalImageInfo(ctx context.Context, cli *client.Client, imageRef string) (*ImageInfo, error) {
	inspect, _, err := cli.ImageInspectWithRaw(ctx, imageRef)
	if err != nil {
		return nil, err
	}

	platform := fmt.Sprintf("%s/%s", inspect.Os, inspect.Architecture)
	info := &ImageInfo{
		Platform: []string{platform}, // Local images have a single platform
	}

	// Check if the image has a descriptor with manifest list media type
	if inspect.Descriptor.MediaType != "" {
		info.IsMultiPlatform = isManifestListMediaType(inspect.Descriptor.MediaType)
	}

	return info, nil
}

// checkRemoteImageInfo checks if a remote image is multiplatform
func checkRemoteImageInfo(ctx context.Context, cli *client.Client, imageRef string) (*ImageInfo, error) {
	distInspect, err := cli.DistributionInspect(ctx, imageRef, "")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect remote image: %w", err)
	}

	info := &ImageInfo{
		IsMultiPlatform: isManifestListMediaType(distInspect.Descriptor.MediaType),
	}

	// Extract platform information from the distribution inspect result
	if len(distInspect.Platforms) > 0 {
		var platforms []string
		for _, platform := range distInspect.Platforms {
			// Skip platforms with empty OS or Architecture
			if platform.OS == "" || platform.Architecture == "" || platform.OS == "unknown" || platform.Architecture == "unknown" {
				continue
			}
			platformStr := fmt.Sprintf("%s/%s", platform.OS, platform.Architecture)
			if platform.Variant != "" {
				platformStr = fmt.Sprintf("%s/%s", platformStr, platform.Variant)
			}
			platforms = append(platforms, platformStr)
		}
		if len(platforms) > 0 {
			info.Platform = platforms
		} else {
			// Fall back to current runtime platform if no valid platforms found
			currentPlatform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
			info.Platform = []string{currentPlatform}
		}
	} else {
		// Fall back to current runtime platform if no platforms are available
		currentPlatform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
		info.Platform = []string{currentPlatform}
	}

	return info, nil
}

// isManifestListMediaType checks if the media type indicates a manifest list
func isManifestListMediaType(mediaType string) bool {
	return mediaType == "application/vnd.docker.distribution.manifest.list.v2+json" ||
		mediaType == "application/vnd.oci.image.index.v1+json"
}

// IsPlatformSupported checks if the given platform is supported by Copa for patching
func IsPlatformSupported(platform string) bool {
	for _, supported := range CopaSupportedPlatforms {
		if platform == supported {
			return true
		}
		// Handle arm64 variants - Copa supports "linux/arm64" which covers "linux/arm64/v8"
		if supported == "linux/arm64" && (platform == "linux/arm64/v8" || platform == "linux/arm64") {
			return true
		}
	}
	return false
}

// FilterSupportedPlatforms returns only the platforms that Copa can patch from the given list
func FilterSupportedPlatforms(platforms []string) []string {
	var supported []string
	for _, platform := range platforms {
		if IsPlatformSupported(platform) {
			supported = append(supported, platform)
		}
	}
	return supported
}

// GetUnsupportedPlatforms returns platforms that Copa cannot patch from the given list
func GetUnsupportedPlatforms(platforms []string) []string {
	var unsupported []string
	for _, platform := range platforms {
		if !IsPlatformSupported(platform) {
			unsupported = append(unsupported, platform)
		}
	}
	return unsupported
}

// GetAllSupportedPlatforms returns a copy of all platforms that Copa supports for patching
func GetAllSupportedPlatforms() []string {
	// Return a copy to prevent modification of the original slice
	supported := make([]string, len(CopaSupportedPlatforms))
	copy(supported, CopaSupportedPlatforms)
	return supported
}
