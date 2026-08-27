package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// mcpServerConfig is the subset of an MCP server entry the structural rules need.
type mcpServerConfig struct {
	Command     string         `json:"command"`
	Args        []string       `json:"args"`
	Env         map[string]any `json:"env"`
	Headers     map[string]any `json:"headers"`
	AutoApprove any            `json:"autoApprove"`
	AlwaysAllow any            `json:"alwaysAllow"`
	Trust       any            `json:"trust"`
}

// serverKey identifies an MCP server by its container ("mcpServers" or
// "servers") and name: the same name in both containers is two servers.
type serverKey struct {
	container, name string
}

func (k serverKey) String() string {
	return k.container + "." + k.name
}

var mcpContainerKeys = []string{"mcpServers", "servers"}

func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// stripJSONC blanks JSONC comments and trailing commas outside strings with
// spaces, preserving doc.content's byte offsets for locate(); comments are
// blanked first so a comma hidden behind one is still found as trailing.
func stripJSONC(content string) string {
	buf := []byte(content)
	blankJSONCComments(buf)
	blankJSONTrailingCommas(buf)
	return string(buf)
}

func blankJSONCComments(buf []byte) {
	inString, escaped := false, false
	for i := 0; i < len(buf); i++ {
		c := buf[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(buf) && buf[i+1] == '/':
			for i < len(buf) && buf[i] != '\n' {
				buf[i] = ' '
				i++
			}
			i--
		case c == '/' && i+1 < len(buf) && buf[i+1] == '*':
			// The opening "/*" is blanked and consumed before the search
			// for "*/" begins, so its own '*' can never double as the
			// first half of the closing delimiter (G4): "/*/" stays open.
			buf[i], buf[i+1] = ' ', ' '
			i += 2
			for i < len(buf) {
				if buf[i] == '\n' {
					i++
					continue
				}
				if buf[i] == '*' && i+1 < len(buf) && buf[i+1] == '/' {
					buf[i], buf[i+1] = ' ', ' '
					i++
					break
				}
				buf[i] = ' '
				i++
			}
			i--
		}
	}
}

func blankJSONTrailingCommas(buf []byte) {
	inString, escaped := false, false
	for i := 0; i < len(buf); i++ {
		c := buf[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c != ',' {
			continue
		}
		k := i + 1
		for k < len(buf) && isJSONSpace(buf[k]) {
			k++
		}
		if k < len(buf) && (buf[k] == '}' || buf[k] == ']') {
			buf[i] = ' '
		}
	}
}

// decodeServerEntry decodes entryRaw's recognised fields independently, so
// a type-mismatched field (e.g. "args": "not-an-array") doesn't hide the
// entry's other fields; fieldErrors names each one that failed to decode.
func decodeServerEntry(entryRaw json.RawMessage) (entry mcpServerConfig, fieldErrors map[string]error, ok bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(entryRaw, &fields); err != nil {
		return mcpServerConfig{}, nil, false
	}
	fieldErrors = map[string]error{}
	decode := func(name string, dst any) {
		raw, present := fields[name]
		if !present {
			return
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			fieldErrors[name] = err
		}
	}
	decode("command", &entry.Command)
	decode("args", &entry.Args)
	decode("env", &entry.Env)
	decode("headers", &entry.Headers)
	decode("autoApprove", &entry.AutoApprove)
	decode("alwaysAllow", &entry.AlwaysAllow)
	decode("trust", &entry.Trust)
	return entry, fieldErrors, true
}

// parseMCPConfig decodes an MCP config's servers, keyed by (container,
// name): a malformed container or entry is skipped, not fatal to the
// others; err is non-nil only if the top level isn't a JSON object.
func parseMCPConfig(path, strippedContent string) (servers map[serverKey]mcpServerConfig, warnings []string, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strippedContent), &top); err != nil {
		return nil, nil, err
	}
	servers = map[serverKey]mcpServerConfig{}
	for _, containerName := range mcpContainerKeys {
		raw, present := top[containerName]
		if !present {
			continue
		}
		var container map[string]json.RawMessage
		if err := json.Unmarshal(raw, &container); err != nil {
			continue
		}
		for name, entryRaw := range container {
			key := serverKey{container: containerName, name: name}
			entry, fieldErrors, ok := decodeServerEntry(entryRaw)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("%s: MCP server %q: entry is not a JSON object", path, key))
				continue
			}
			servers[key] = entry
			for field, ferr := range fieldErrors {
				warnings = append(warnings, fmt.Sprintf("%s: MCP server %q: field %q: %v", path, key, field, ferr))
			}
		}
	}
	sort.Strings(warnings)
	return servers, warnings, nil
}

func sortedServerKeys(servers map[serverKey]mcpServerConfig) []serverKey {
	keys := make([]serverKey, 0, len(servers))
	for k := range servers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].container != keys[j].container {
			return keys[i].container < keys[j].container
		}
		return keys[i].name < keys[j].name
	})
	return keys
}

// serverSpan is the byte span of one server's JSON object within the
// document's (comment-blanked, offset-preserving) content.
type serverSpan struct {
	start, end int
}

// rawStringSpan returns a string token's raw quoted span given before (the
// decoder's offset just prior to reading it) and after (its InputOffset
// once read); reliable even with escapes since no `"` precedes it.
func rawStringSpan(text string, before, after int) span {
	rel := strings.IndexByte(text[before:], '"')
	return span{start: before + rel + 1, end: after - 1}
}

// buildMCPStructuralIndex walks stripped's JSON tokens once, building each
// server's object span and the byte spans of its env/headers secret-shaped
// literal values (G1.1.b), so locating all of it costs O(file size).
func buildMCPStructuralIndex(stripped string) (servers map[serverKey]serverSpan, secretValueSpans []span) {
	type frame struct {
		isObject          bool
		isRoot            bool
		isContainer       bool
		containerName     string
		isEntry           bool
		key               serverKey
		isSecretContainer bool
		awaitingValue     bool
		pendingKey        string
	}

	servers = map[serverKey]serverSpan{}
	stack := []frame{{}} // seed: ground level below the document's own root value

	dec := json.NewDecoder(strings.NewReader(stripped))
	for {
		before := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			break // EOF, or malformed JSON beyond this point: keep what was indexed so far
		}

		top := &stack[len(stack)-1]
		delim, isDelim := tok.(json.Delim)
		if !isDelim {
			if top.isObject {
				if !top.awaitingValue {
					if s, ok := tok.(string); ok {
						top.pendingKey = s
						top.awaitingValue = true
					}
				} else {
					if s, ok := tok.(string); ok && top.isSecretContainer &&
						secretKeyRe.MatchString(top.pendingKey) && !maskExempt(s) {
						secretValueSpans = append(secretValueSpans, rawStringSpan(stripped, int(before), int(dec.InputOffset())))
					}
					top.awaitingValue = false
				}
			}
			continue
		}

		switch delim {
		case '{', '[':
			nf := frame{isObject: delim == '{'}
			switch {
			case len(stack) == 1 && nf.isObject:
				nf.isRoot = true
			case top.isRoot && top.awaitingValue && nf.isObject &&
				(top.pendingKey == "mcpServers" || top.pendingKey == "servers"):
				nf.isContainer = true
				nf.containerName = top.pendingKey
			case top.isContainer && top.awaitingValue && nf.isObject:
				nf.isEntry = true
				nf.key = serverKey{container: top.containerName, name: top.pendingKey}
				servers[nf.key] = serverSpan{start: int(before)}
			case top.isEntry && top.awaitingValue && nf.isObject &&
				(top.pendingKey == "env" || top.pendingKey == "headers"):
				nf.isSecretContainer = true
			}
			if top.isObject {
				top.awaitingValue = false
			}
			stack = append(stack, nf)
		case '}', ']':
			finished := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if finished.isEntry {
				if sp, ok := servers[finished.key]; ok {
					sp.end = int(dec.InputOffset())
					servers[finished.key] = sp
				}
			}
		}
	}
	return servers, secretValueSpans
}

// serverBlockFor returns the byte span of a server's JSON object, if the
// index has a well-formed (non-empty) span for it.
func serverBlockFor(idx map[serverKey]serverSpan, key serverKey) (start, end int, ok bool) {
	sp, found := idx[key]
	if !found || sp.end <= sp.start {
		return 0, 0, false
	}
	return sp.start, sp.end, true
}

// locateKeyInBlock finds the line/column of a quoted key within [start, end)
// of the JSONC-stripped content, so a key mentioned only inside a comment
// never wins; falls back to (1, 1) per the JSON-location spec.
func locateKeyInBlock(doc document, stripped string, start, end int, key string) (line, col int) {
	block := stripped[start:end]
	idx := strings.Index(block, `"`+key+`"`)
	if idx == -1 {
		return 1, 1
	}
	return doc.locate(start + idx)
}
