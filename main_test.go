package main

import (
	"testing"
)

func TestVersionVariables(t *testing.T) {
	// Test that version variables are defined
	if version == "" {
		t.Error("version should not be empty")
	}

	if commit == "" {
		t.Error("commit should not be empty")
	}

	if date == "" {
		t.Error("date should not be empty")
	}

	// Test default values
	if version != "dev" {
		t.Logf("version is set to: %s", version)
	}

	if commit != "none" {
		t.Logf("commit is set to: %s", commit)
	}

	if date != "unknown" {
		t.Logf("date is set to: %s", date)
	}
}
