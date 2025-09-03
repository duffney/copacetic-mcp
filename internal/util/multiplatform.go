// Package multiplatform provides utilities to detect if Docker images support multiple platforms.
package multiplatform

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// CopaSupportedPlatforms lists all platforms that Copa can patch
// Based on Copa documentation: https://project-copacetic.github.io/copacetic/website/multiplatform-patching
// TODO: mv to copa internal pkg
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
	if inspect.Descriptor != nil && inspect.Descriptor.MediaType != "" {
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

func PlatformToArch(platform string) string {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return platform // fallback if invalid format
	}

	arch := parts[1] // e.g., "amd64", "arm", "arm64"

	if len(parts) > 2 {
		// Handle cases like linux/arm/v6, linux/arm/v7
		variant := parts[2]
		return arch + "-" + variant
	}

	return arch
}

// ResolvePlatformSpecificDigest resolves an image reference to a platform-specific digest
// Returns the original image reference if resolution fails or if it's already a digest reference
func ResolvePlatformSpecificDigest(imageRef, platform string) (string, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef, fmt.Errorf("failed to parse image reference %s: %w", imageRef, err)
	}

	// If it's already a digest reference, return as-is
	if _, ok := ref.(name.Digest); ok {
		return imageRef, nil
	}

	// Only handle tag references
	tagged, ok := ref.(name.Tag)
	if !ok {
		return imageRef, fmt.Errorf("unsupported reference type for %s", imageRef)
	}

	repository := tagged.RepositoryStr()
	repository = strings.TrimPrefix(repository, "library/")

	// Parse platform (e.g., "linux/amd64" -> "linux", "amd64")
	platformParts := strings.Split(platform, "/")
	if len(platformParts) != 2 {
		return imageRef, fmt.Errorf("invalid platform format %s, expected OS/ARCH", platform)
	}

	// Create platform spec
	platformSpec := v1.Platform{
		OS:           platformParts[0],
		Architecture: platformParts[1],
	}

	// Get the descriptor
	desc, err := remote.Get(ref)
	if err != nil {
		return imageRef, fmt.Errorf("could not get manifest for %s: %w", imageRef, err)
	}

	// Try to get as manifest list/index first
	idx, err := desc.ImageIndex()
	if err != nil {
		// Not a manifest list, try as single image
		_, err := desc.Image()
		if err != nil {
			return imageRef, fmt.Errorf("could not parse manifest for %s: %w", imageRef, err)
		}
		// Single platform image, use its digest
		digest := desc.Digest.String()
		return fmt.Sprintf("%s@%s", repository, digest), nil
	}

	// It's a manifest list/index - find the platform-specific manifest
	manifest, err := idx.IndexManifest()
	if err != nil {
		return imageRef, fmt.Errorf("could not get index manifest for %s: %w", imageRef, err)
	}

	// Find the platform-specific digest
	for _, m := range manifest.Manifests {
		if m.Platform != nil &&
			m.Platform.OS == platformSpec.OS &&
			m.Platform.Architecture == platformSpec.Architecture {
			platformDigest := m.Digest.String()
			return fmt.Sprintf("%s@%s", repository, platformDigest), nil
		}
	}

	return imageRef, fmt.Errorf("could not find platform %s in manifest list", platform)
}
