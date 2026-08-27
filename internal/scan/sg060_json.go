package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/CrescentKohana/skillguard/internal/finding"
)

var secretKeyRe = regexp.MustCompile(`(?i)key|token|secret|password|passwd|authorization`)

// isPlaceholderValue reports whether v looks like a template placeholder
// rather than a real secret, per the SG060 exclusion list.
func isPlaceholderValue(v string) bool {
	if strings.Contains(v, "${") || strings.Contains(v, "<") || strings.Contains(v, "{{") {
		return true
	}
	if strings.HasPrefix(v, "$") {
		return true
	}
	lower := strings.ToLower(v)
	for _, p := range []string{"your_", "xxxx", "example", "changeme", "replace"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// secretKV is one credential-shaped key/value pair found under a server's
// env or headers map.
type secretKV struct {
	Key, Value string
}

// secretEnvPairs returns every (key, value) pair in m whose key name
// suggests a credential and whose value is a non-placeholder literal of
// length >= 8, sorted by key.
func secretEnvPairs(m map[string]any) []secretKV {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []secretKV
	for _, k := range keys {
		v, isStr := m[k].(string)
		if !isStr || !secretKeyRe.MatchString(k) {
			continue
		}
		if len([]rune(v)) < 8 || isPlaceholderValue(v) {
			continue
		}
		out = append(out, secretKV{Key: k, Value: v})
	}
	return out
}

// sg060JSONEnv flags opaque secret-shaped values under a server's env or
// headers map whose key name suggests a credential; the value is masked
// explicitly since it need not match any SG060 pattern.
func sg060JSONEnv(doc document, stripped string, servers map[serverKey]mcpServerConfig, idx map[serverKey]serverSpan, sc *snippetCache) []finding.Finding {
	var out []finding.Finding
	for _, key := range sortedServerKeys(servers) {
		s := servers[key]
		start, end, hasBlock := serverBlockFor(idx, key)
		for _, m := range []map[string]any{s.Env, s.Headers} {
			for _, kv := range secretEnvPairs(m) {
				line, col := 1, 1
				if hasBlock {
					line, col = locateKeyInBlock(doc, stripped, start, end, kv.Key)
				}
				out = append(out, finding.Finding{
					RuleID: "SG060", Severity: finding.SeverityCritical, Line: line, Column: col,
					Message: fmt.Sprintf("hardcoded secret in %q for MCP server %q: %s", kv.Key, key, maskSecret(kv.Value)),
					Snippet: sc.at(line),
				})
			}
		}
	}
	return out
}
