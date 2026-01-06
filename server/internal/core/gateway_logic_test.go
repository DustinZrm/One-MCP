package core

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestPermissionLogic(t *testing.T) {
	// Tests the exported CheckPermission function directly from gateway.go

	t.Run("Empty Config Allows All", func(t *testing.T) {
		assert.True(t, CheckPermission(nil, nil, "1", "srv1__tool1"))
		assert.True(t, CheckPermission([]string{}, []string{}, "1", "srv1__tool1"))
	})

	t.Run("Server Restriction", func(t *testing.T) {
		allowedSrv := []string{"1", "2"}
		assert.True(t, CheckPermission(allowedSrv, nil, "1", "srv1__tool1"))
		assert.True(t, CheckPermission(allowedSrv, nil, "2", "srv2__tool1"))
		assert.False(t, CheckPermission(allowedSrv, nil, "3", "srv3__tool1"))
	})

	t.Run("Tool Restriction", func(t *testing.T) {
		allowedTools := []string{"srv1__toolA"}
		// Should only allow toolA
		assert.True(t, CheckPermission(nil, allowedTools, "1", "srv1__toolA"))
		assert.False(t, CheckPermission(nil, allowedTools, "1", "srv1__toolB"))
		// Even if server restriction is empty (which usually means all), tool restriction takes precedence?
		// Logic: if len(allowedToolMap) > 0 -> check tools.
		// So yes, if I specify tools, I am locked to those tools.
		assert.False(t, CheckPermission(nil, allowedTools, "2", "srv2__toolA")) // Assuming full name match
	})

	t.Run("Tool Wildcard", func(t *testing.T) {
		allowedTools := []string{"*"}
		assert.True(t, CheckPermission(nil, allowedTools, "1", "srv1__toolA"))
		assert.True(t, CheckPermission(nil, allowedTools, "99", "srv99__any"))
	})

	t.Run("Mixed Restrictions", func(t *testing.T) {
		// Allowed Servers: [1], Allowed Tools: [srv2__toolA]
		// Logic: if len(allowedToolMap) > 0, it returns result of tool check.
		// It does NOT fall back to server check if tool check fails?
		// Current logic:
		/*
			if len(allowedToolMap) > 0 {
				if allowedToolMap["*"] { return true }
				return allowedToolMap[toolName]
			}
			// Fallback
		*/
		// So if I have ANY tool restrictions, Server restrictions are IGNORED.

		allowedSrv := []string{"1"}
		allowedTools := []string{"srv2__toolA"}

		// Expectation: accessing srv2__toolA -> True
		assert.True(t, CheckPermission(allowedSrv, allowedTools, "2", "srv2__toolA"))

		// Expectation: accessing srv1__toolB -> ?
		// Tool map has entries. It checks map. "srv1__toolB" is not in map. Returns false.
		// Even though Server 1 is in AllowedServers.
		// This means defining specific tools OVERRIDES server-level permissions completely.
		assert.False(t, CheckPermission(allowedSrv, allowedTools, "1", "srv1__toolB"))
	})
}
