package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds user configurable settings for ShellShare.
type Config struct {
	SignalingURL            string
	FallbackRelay           string
	AutoApproveGuests       bool
	FingerprintVerification bool
	SessionTimeout          time.Duration
	ShowJoinNotifications   bool
	ColorScheme             string
	Name                    string
	ReadOnly                bool
	AllowWrite              bool
	ForwardTarget           string
	ForwardListen           string
	RecordPath              string
}

// Default returns the baseline configuration.
func Default() Config {
	return Config{
		SignalingURL:            "ws://localhost:7777/ws",
		FallbackRelay:           "",
		AutoApproveGuests:       false,
		FingerprintVerification: true,
		SessionTimeout:          time.Hour,
		ShowJoinNotifications:   true,
		ColorScheme:             "auto",
		ReadOnly:                true,
		AllowWrite:              false,
		RecordPath:              "",
	}
}

// Load returns configuration merged from defaults, a config.toml file if present,
// and environment overrides. The parser intentionally supports only the keys
func Load(optionalPath string) (Config, error) {
	cfg := Default()
	path := optionalPath
	if path == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			path = filepath.Join(home, ".shellshare", "config.toml")
		}
	}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			parseTOML(string(data), &cfg)
		}
	}
	// Environment overrides are handy in containers/CI.
	if v := os.Getenv("SHELLSHARE_SIGNALING_URL"); v != "" {
		cfg.SignalingURL = v
	}
	if v := os.Getenv("SHELLSHARE_NAME"); v != "" {
		cfg.Name = v
	}
	if v := os.Getenv("SHELLSHARE_ALLOW_WRITE"); strings.EqualFold(v, "true") {
		cfg.AllowWrite = true
		cfg.ReadOnly = false
	}
	if v := os.Getenv("SHELLSHARE_READ_ONLY"); strings.EqualFold(v, "false") {
		cfg.ReadOnly = false
	}
	return cfg, nil
}

// parseTOML is a lightweight parser that understands the sample config
func parseTOML(body string, cfg *Config) {
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"`)
		switch section + "." + strings.ToLower(key) {
		case "server.signaling_url":
			cfg.SignalingURL = val
		case "server.fallback_relay":
			cfg.FallbackRelay = val
		case "server.forward_target":
			cfg.ForwardTarget = val
		case "server.forward_listen":
			cfg.ForwardListen = val
		case "security.auto_approve_guests":
			cfg.AutoApproveGuests = parseBool(val, cfg.AutoApproveGuests)
		case "security.fingerprint_verification":
			cfg.FingerprintVerification = parseBool(val, cfg.FingerprintVerification)
		case "security.session_timeout":
			if seconds, err := strconv.Atoi(val); err == nil {
				cfg.SessionTimeout = time.Duration(seconds) * time.Second
			}
		case "display.show_join_notifications":
			cfg.ShowJoinNotifications = parseBool(val, cfg.ShowJoinNotifications)
		case "display.color_scheme":
			cfg.ColorScheme = val
		}
	}
}

func parseBool(val string, fallback bool) bool {
	switch strings.ToLower(val) {
	case "true", "yes", "1", "on":
		return true
	case "false", "no", "0", "off":
		return false
	default:
		return fallback
	}
}
