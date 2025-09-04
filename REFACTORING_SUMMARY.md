# Refactoring Summary: Decoupled Vulnerability Scanning

## Overview

Successfully refactored the MCP server to decouple the Trivy vulnerability scanning logic from the report-based patching functionality. This creates a cleaner separation of concerns and provides more flexibility for users.

## Changes Made

### 1. New MCP Tool: `scan-container`

- **Purpose**: Dedicated tool for vulnerability scanning using Trivy
- **Description**: "Scan container image for vulnerabilities using Trivy - creates vulnerability reports required for report-based patching"
- **Parameters**:
  - `image`: Container image to scan
  - `platform`: Optional array of platforms to scan (defaults to host platform)
- **Returns**: Scan results including vulnerability count, report directory path, and usage instructions

### 2. Updated MCP Tool: `patch-vulnerabilities`

- **Previous behavior**: Automatically performed Trivy scan before patching
- **New behavior**: Requires pre-generated vulnerability report from `scan-container` tool
- **Updated Description**: "Patch container image vulnerabilities using a pre-generated vulnerability report from 'scan-container' tool - requires running 'scan-container' first"
- **New Parameter**: `reportPath` - Path to vulnerability report directory (required)
- **Removed Parameter**: `platform` - No longer needed since report contains platform info

### 3. Enhanced Type Definitions

- **New Types**:
  - `ScanParams`: Parameters for vulnerability scanning
  - `ScanResult`: Results from vulnerability scanning
- **Updated Types**:
  - `ReportBasedPatchParams`: Now requires `reportPath` instead of `platform`
  - Added clear documentation about prerequisite `scan-container` step

### 4. Enhanced Trivy Module

- **New Function**: `Scan()` - Returns detailed scan results with vulnerability counts
- **Enhanced Function**: `countVulnerabilitiesInReport()` - Counts vulnerabilities across all report files
- **New Function**: `countVulnerabilitiesInFile()` - Counts vulnerabilities in individual JSON reports

### 5. Updated Client Testing

- Updated `cmd/client/main.go` to test the new workflow
- Added tool listing to show all available MCP tools
- Demonstrates proper error handling for missing report paths
- Created `cmd/workflow-demo/main.go` for complete workflow demonstration

## Workflow Changes

### Before (Coupled)

1. Call `patch-vulnerabilities` with image and platform
2. Tool automatically scans image with Trivy
3. Tool patches based on scan results
4. Scan report is deleted after patching

### After (Decoupled)

1. Call `scan-container` with image and platform(s)
2. Receive scan results and report directory path
3. Call `patch-vulnerabilities` with image and report path
4. Tool patches based on existing scan results
5. Scan report is preserved for potential reuse

## Benefits

### 1. Separation of Concerns

- Scanning and patching are now distinct operations
- Each tool has a single, well-defined responsibility
- Easier to test and maintain individual components

### 2. Improved Flexibility

- Users can scan once and patch multiple times with different parameters
- Scan reports can be inspected before patching
- Supports different scanning strategies without affecting patching logic

### 3. Better Error Handling

- Clear error messages when report path is missing
- Validation that report directory exists before attempting to patch
- Guidance to users about required prerequisite steps

### 4. Enhanced User Experience

- Clear workflow: scan first, then patch
- Informative scan results show vulnerability counts and platforms
- Report paths are preserved for potential reuse
- Tool descriptions clearly indicate dependencies

## Testing Verification

All existing tests pass, and the new functionality has been verified through:

- Individual tool testing via updated client
- Complete workflow demonstration via workflow-demo
- Error handling validation for missing/invalid report paths
- Tool listing verification showing new tools are properly registered

## Backward Compatibility

- Existing `patch-comprehensive` and `patch-platforms` tools remain unchanged
- All type definitions maintain compatibility for non-scanning workflows
- Legacy functionality preserved while adding new capabilities

## Usage Examples

### Scan Container

```json
{
  "name": "scan-container",
  "arguments": {
    "image": "alpine:3.17",
    "platform": ["linux/amd64", "linux/arm64"]
  }
}
```

### Patch Vulnerabilities

```json
{
  "name": "patch-vulnerabilities",
  "arguments": {
    "image": "alpine:3.17",
    "patchtag": "alpine-patched",
    "push": false,
    "reportPath": "/tmp/reports-123456"
  }
}
```
