package shellshare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shellshare/pkg/signaling"
)

// ServeSignaling launches the lightweight signaling server on addr (e.g. ":7777").
func ServeSignaling(ctx context.Context, addr string) error {
	if addr == "" {
		addr = ":7777"
	}
	server := signaling.NewServer(addr)
	fmt.Printf("ShellShare signaling server listening on %s\n", addr)
	return server.ListenAndServe(ctx)
}

// SessionInfo mirrors the /sessions API response.
type SessionInfo struct {
	ID        string    `json:"id"`
	Guests    int       `json:"guests"`
	StartedAt time.Time `json:"started_at"`
}

// ListSessions retrieves active sessions from the signaling server.
func ListSessions(signalingURL string) ([]SessionInfo, error) {
	base, err := httpBase(signalingURL)
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(base + "/sessions")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Sessions, nil
}

func httpBase(websocketURL string) (string, error) {
	u, err := url.Parse(websocketURL)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	u.Path = ""
	u.RawQuery = ""
	return strings.TrimRight(u.String(), "/"), nil
}
