package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Summary renders the startup provenance report (concept ch. 3.3): every
// security-relevant key with the source it was resolved from — but never the
// content of a value that could carry credentials (http.addr, database.url,
// oidc.issuer). Only non-secret descriptors are shown: the schema version,
// the mode and the bypass flag state.
func (c *Config) Summary() string {
	src := func(key string) string {
		if s, ok := c.sources[key]; ok {
			return string(s)
		}
		return string(SourceDefault)
	}

	var b strings.Builder
	line := func(key, state string) {
		fmt.Fprintf(&b, "config: %-20s %s (source=%s)\n", key+":", state, src(key))
	}

	line("schema_version", strconv.Itoa(c.SchemaVersion))
	line("env", c.Env)
	line("http.addr", "set")
	line("database.url", "set")
	line("oidc.issuer", "set")
	line("auth.bypass_enabled", strconv.FormatBool(c.Auth.BypassEnabled))
	return b.String()
}
