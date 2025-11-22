package signaling

import "encoding/json"

// Envelope wraps all websocket messages so the server can route and validate them.
type Envelope struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	SenderID  string          `json:"sender_id,omitempty"`
	TargetID  string          `json:"target_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Announce is sent by hosts to publish a new session.
type Announce struct {
	PublicKey    string   `json:"public_key"`
	Capabilities []string `json:"capabilities,omitempty"`
	AllowWrite   bool     `json:"allow_write"`
	ReadOnly     bool     `json:"read_only"`
	Name         string   `json:"name,omitempty"`
	DirectAddr   string   `json:"direct_addr,omitempty"`
}

// Join is sent by guests to connect to an existing session.
type Join struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name,omitempty"`
}

// HostOffer is returned to guests once the host is found.
type HostOffer struct {
	PublicKey  string `json:"public_key"`
	SessionID  string `json:"session_id"`
	AllowWrite bool   `json:"allow_write"`
	Name       string `json:"name,omitempty"`
	DirectAddr string `json:"direct_addr,omitempty"`
}

// GuestJoined notifies hosts of a new participant.
type GuestJoined struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name,omitempty"`
}

// GuestLeft notifies hosts that a participant disconnected.
type GuestLeft struct {
	UserID string `json:"user_id"`
}

// TermData carries encrypted terminal data (stdout/stderr) from host to guests.
type TermData struct {
	Data      string `json:"data"`
	Sequence  int64  `json:"sequence"`
	Timestamp int64  `json:"timestamp"`
}

// TermInput carries encrypted keystrokes from guest to host.
type TermInput struct {
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

// Control wraps permission updates.
type Control struct {
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Allow  bool   `json:"allow"`
}

// Forwarding messages (relay-based).
type ForwardInit struct {
	TunnelID string `json:"tunnel_id"`
}

type ForwardAck struct {
	TunnelID string `json:"tunnel_id"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

type ForwardData struct {
	TunnelID string `json:"tunnel_id"`
	Data     string `json:"data"`
}

type ForwardClose struct {
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason,omitempty"`
}

// ErrorMessage provides lightweight error context to clients.
type ErrorMessage struct {
	Message string `json:"message"`
}
