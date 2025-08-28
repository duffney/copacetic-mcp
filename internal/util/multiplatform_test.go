package multiplatform

import (
	"context"
	"io"
	"testing"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

func TestGetImageInfo_LocalImage(t *testing.T) {
	ctx := context.Background()

	// Test with a common local image that should exist or can be pulled
	testCases := []struct {
		name     string
		imageRef string
	}{
		{
			name:     "alpine image",
			imageRef: "alpine:latest",
		},
		{
			name:     "hello-world image",
			imageRef: "hello-world:latest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Try to pull the image first to ensure it's available locally
			cli, err := client.NewClientWithOpts(
				client.FromEnv,
				client.WithAPIVersionNegotiation(),
			)
			if err != nil {
				t.Skipf("Failed to create Docker client: %v", err)
			}
			defer cli.Close()

			// Pull the image to ensure it's local
			reader, err := cli.ImagePull(ctx, tc.imageRef, image.PullOptions{})
			if err != nil {
				t.Skipf("Failed to pull image %s: %v", tc.imageRef, err)
			}
			defer reader.Close()
			// Consume the reader to complete the pull
			io.Copy(io.Discard, reader)

			// Test our function
			info, err := GetImageInfo(ctx, tc.imageRef)
			if err != nil {
				t.Fatalf("GetImageInfo failed: %v", err)
			}

			// Verify the image is detected as local
			if !info.IsLocal {
				t.Error("Expected image to be detected as local")
			}

			// Verify Platform field is populated
			if len(info.Platform) == 0 {
				t.Error("Expected Platform field to be populated for local image")
			}

			// Verify platform format
			for _, platform := range info.Platform {
				if platform == "" {
					t.Error("Platform should not be empty")
				}
				t.Logf("Local image platform: %s", platform)
			}
		})
	}
}

func TestGetImageInfo_RemoteImage(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name           string
		imageRef       string
		expectMulti    *bool // nil means don't check, true/false means check
		minPlatforms   int
	}{
		{
			name:           "alpine image (typically multiplatform)",
			imageRef:       "alpine:3.17",
			expectMulti:    nil, // Don't check multiplatform, just verify platform population
			minPlatforms:   1,
		},
		{
			name:           "nginx multiplatform image",
			imageRef:       "nginx:latest",
			expectMulti:    func() *bool { b := true; return &b }(), // expect multiplatform
			minPlatforms:   2, // nginx typically supports multiple platforms
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Remove local image first to force remote lookup
			cli, err := client.NewClientWithOpts(
				client.FromEnv,
				client.WithAPIVersionNegotiation(),
			)
			if err != nil {
				t.Skipf("Failed to create Docker client: %v", err)
			}
			defer cli.Close()

			// Try to remove the image to ensure we're testing remote lookup
			cli.ImageRemove(ctx, tc.imageRef, image.RemoveOptions{Force: true})

			// Test our function
			info, err := GetImageInfo(ctx, tc.imageRef)
			if err != nil {
				t.Fatalf("GetImageInfo failed: %v", err)
			}

			// Verify the image is detected as remote
			if info.IsLocal {
				t.Error("Expected image to be detected as remote")
			}

			// Verify Platform field is populated
			if len(info.Platform) == 0 {
				t.Error("Expected Platform field to be populated for remote image")
			}

			// Verify minimum platform count
			if len(info.Platform) < tc.minPlatforms {
				t.Errorf("Expected at least %d platforms, got %d", tc.minPlatforms, len(info.Platform))
			}

			// Verify multiplatform detection matches expectation (if specified)
			if tc.expectMulti != nil && info.IsMultiPlatform != *tc.expectMulti {
				t.Errorf("Expected IsMultiPlatform to be %v, got %v", *tc.expectMulti, info.IsMultiPlatform)
			}

			// Verify platform formats
			for _, platform := range info.Platform {
				if platform == "" {
					t.Error("Platform should not be empty")
				}
				t.Logf("Remote image platform: %s", platform)
			}
		})
	}
}

func TestCheckLocalImageInfo(t *testing.T) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Skipf("Failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Pull a simple image
	imageRef := "hello-world:latest"
	reader, err := cli.ImagePull(ctx, imageRef, image.PullOptions{})
	if err != nil {
		t.Skipf("Failed to pull image %s: %v", imageRef, err)
	}
	defer reader.Close()
	// Consume the reader to complete the pull
	io.Copy(io.Discard, reader)

	info, err := checkLocalImageInfo(ctx, cli, imageRef)
	if err != nil {
		t.Fatalf("checkLocalImageInfo failed: %v", err)
	}

	// Verify Platform field is populated and has exactly one platform
	if len(info.Platform) != 1 {
		t.Errorf("Expected exactly 1 platform for local image, got %d", len(info.Platform))
	}

	if info.Platform[0] == "" {
		t.Error("Platform should not be empty")
	}

	t.Logf("Local image platform: %s", info.Platform[0])
}

func TestCheckRemoteImageInfo(t *testing.T) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Skipf("Failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Test with a known multiplatform image
	imageRef := "alpine:latest"

	info, err := checkRemoteImageInfo(ctx, cli, imageRef)
	if err != nil {
		t.Fatalf("checkRemoteImageInfo failed: %v", err)
	}

	// Verify Platform field is populated
	if len(info.Platform) == 0 {
		t.Error("Expected Platform field to be populated for remote image")
	}

	// Verify all platforms are non-empty
	for i, platform := range info.Platform {
		if platform == "" {
			t.Errorf("Platform[%d] should not be empty", i)
		}
		t.Logf("Remote image platform: %s", platform)
	}
}

func TestFilterSupportedPlatforms(t *testing.T) {
	testCases := []struct {
		name      string
		platforms []string
		expected  []string
	}{
		{
			name:      "all supported platforms",
			platforms: []string{"linux/amd64", "linux/arm64", "linux/arm/v7"},
			expected:  []string{"linux/amd64", "linux/arm64", "linux/arm/v7"},
		},
		{
			name:      "mixed supported and unsupported",
			platforms: []string{"linux/amd64", "windows/amd64", "linux/arm64", "darwin/amd64"},
			expected:  []string{"linux/amd64", "linux/arm64"},
		},
		{
			name:      "no supported platforms",
			platforms: []string{"windows/amd64", "darwin/amd64"},
			expected:  []string{},
		},
		{
			name:      "empty input",
			platforms: []string{},
			expected:  []string{},
		},
		{
			name:      "arm64 variants",
			platforms: []string{"linux/arm64/v8", "linux/arm64"},
			expected:  []string{"linux/arm64/v8", "linux/arm64"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := FilterSupportedPlatforms(tc.platforms)

			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d platforms, got %d", len(tc.expected), len(result))
			}

			// Check that all expected platforms are present
			expectedMap := make(map[string]bool)
			for _, platform := range tc.expected {
				expectedMap[platform] = true
			}

			for _, platform := range result {
				if !expectedMap[platform] {
					t.Errorf("Unexpected platform in result: %s", platform)
				}
			}

			// Check that all result platforms are expected
			resultMap := make(map[string]bool)
			for _, platform := range result {
				resultMap[platform] = true
			}

			for _, platform := range tc.expected {
				if !resultMap[platform] {
					t.Errorf("Expected platform not found in result: %s", platform)
				}
			}
		})
	}
}

func TestIsPlatformSupported(t *testing.T) {
	testCases := []struct {
		platform string
		expected bool
	}{
		{"linux/amd64", true},
		{"linux/arm64", true},
		{"linux/arm64/v8", true}, // Should be supported as variant of arm64
		{"linux/arm/v7", true},
		{"linux/arm/v6", true},
		{"linux/386", true},
		{"linux/ppc64le", true},
		{"linux/s390x", true},
		{"linux/riscv64", true},
		{"windows/amd64", false},
		{"darwin/amd64", false},
		{"linux/mips", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.platform, func(t *testing.T) {
			result := IsPlatformSupported(tc.platform)
			if result != tc.expected {
				t.Errorf("IsPlatformSupported(%q) = %v, expected %v", tc.platform, result, tc.expected)
			}
		})
	}
}
