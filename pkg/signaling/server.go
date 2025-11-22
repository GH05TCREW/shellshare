package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"shellshare/internal/websocket"
)

// Server implements a lightweight signaling server suitable for local dev or self-hosting.
type Server struct {
	Addr string

	mu       sync.Mutex
	sessions map[string]*sessionState
	httpSrv  *http.Server
}

type sessionState struct {
	ID             string
	Host           *peerConn
	Guests         map[string]*peerConn
	AllowWriteAll  bool
	WriteOverrides map[string]bool
	CreatedAt      time.Time
}

type peerConn struct {
	ID        string
	Name      string
	Role      string // host or guest
	PublicKey string
	ws        *websocket.Conn
	send      chan Envelope
	server    *Server
	sessionID string
}

// NewServer returns a configured server bound to addr (e.g. ":7777").
func NewServer(addr string) *Server {
	return &Server{
		Addr:     addr,
		sessions: make(map[string]*sessionState),
	}
}

// ListenAndServe starts the HTTP/WebSocket server and blocks until ctx is canceled or the server exits.
func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/ws", websocket.Handler(s.handleWS))
	mux.HandleFunc("/sessions", s.handleList)

	s.httpSrv = &http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = s.httpSrv.Close()
	}()

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.httpSrv.Serve(ln)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	type sessionInfo struct {
		ID        string    `json:"id"`
		Guests    int       `json:"guests"`
		StartedAt time.Time `json:"started_at"`
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := struct {
		Sessions []sessionInfo `json:"sessions"`
	}{}
	for _, sess := range s.sessions {
		resp.Sessions = append(resp.Sessions, sessionInfo{
			ID:        sess.ID,
			Guests:    len(sess.Guests),
			StartedAt: sess.CreatedAt,
		})
	}
	data, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) handleWS(conn *websocket.Conn) {
	defer conn.Close()
	var hello Envelope
	if err := websocket.JSON.Receive(conn, &hello); err != nil {
		return
	}
	switch hello.Type {
	case "announce":
		s.handleAnnounce(conn, hello)
	case "join":
		s.handleJoin(conn, hello)
	default:
		_ = websocket.JSON.Send(conn, Envelope{
			Type:    "error",
			Payload: mustJSON(ErrorMessage{Message: "unsupported handshake"}),
		})
	}
}

func (s *Server) handleAnnounce(conn *websocket.Conn, env Envelope) {
	var announce Announce
	if err := json.Unmarshal(env.Payload, &announce); err != nil {
		_ = websocket.JSON.Send(conn, Envelope{Type: "error", Payload: mustJSON(ErrorMessage{Message: "bad announce payload"})})
		return
	}
	host := &peerConn{
		ID:        "host",
		Name:      announce.Name,
		Role:      "host",
		PublicKey: announce.PublicKey,
		ws:        conn,
		send:      make(chan Envelope, 8),
		server:    s,
		sessionID: env.SessionID,
	}
	s.mu.Lock()
	if _, ok := s.sessions[env.SessionID]; ok {
		s.mu.Unlock()
		_ = websocket.JSON.Send(conn, Envelope{Type: "error", Payload: mustJSON(ErrorMessage{Message: "session already exists"})})
		return
	}
	sess := &sessionState{
		ID:             env.SessionID,
		Host:           host,
		Guests:         make(map[string]*peerConn),
		AllowWriteAll:  announce.AllowWrite && !announce.ReadOnly,
		WriteOverrides: make(map[string]bool),
		CreatedAt:      time.Now(),
	}
	s.sessions[env.SessionID] = sess
	s.mu.Unlock()

	go host.writePump()
	_ = websocket.JSON.Send(conn, Envelope{
		Type:     "session_ready",
		SenderID: "server",
		Payload: mustJSON(HostOffer{
			PublicKey:  announce.PublicKey,
			SessionID:  env.SessionID,
			AllowWrite: sess.AllowWriteAll,
			Name:       announce.Name,
			DirectAddr: announce.DirectAddr,
		}),
	})
	s.listenHost(sess, host)
}

func (s *Server) handleJoin(conn *websocket.Conn, env Envelope) {
	var join Join
	if err := json.Unmarshal(env.Payload, &join); err != nil {
		_ = websocket.JSON.Send(conn, Envelope{Type: "error", Payload: mustJSON(ErrorMessage{Message: "bad join payload"})})
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[env.SessionID]
	if !ok {
		s.mu.Unlock()
		_ = websocket.JSON.Send(conn, Envelope{Type: "error", Payload: mustJSON(ErrorMessage{Message: "session not found"})})
		return
	}
	guest := &peerConn{
		ID:        env.SenderID,
		Name:      join.Name,
		Role:      "guest",
		PublicKey: join.PublicKey,
		ws:        conn,
		send:      make(chan Envelope, 8),
		server:    s,
		sessionID: env.SessionID,
	}
	sess.Guests[guest.ID] = guest
	s.mu.Unlock()

	go guest.writePump()

	// send host offer to guest
	_ = websocket.JSON.Send(conn, Envelope{
		Type:     "host_offer",
		SenderID: "server",
		Payload: mustJSON(HostOffer{
			PublicKey:  sess.Host.PublicKey,
			SessionID:  sess.ID,
			AllowWrite: sess.AllowWriteAll,
			Name:       sess.Host.Name,
		}),
	})
	// notify host
	sess.Host.send <- Envelope{
		Type:      "guest_joined",
		SessionID: sess.ID,
		SenderID:  guest.ID,
		Payload: mustJSON(GuestJoined{
			UserID:    guest.ID,
			PublicKey: guest.PublicKey,
			Name:      guest.Name,
		}),
	}
	s.listenGuest(sess, guest)
}

func (s *Server) listenHost(sess *sessionState, host *peerConn) {
	defer s.dropSession(sess.ID)
	for {
		var env Envelope
		if err := websocket.JSON.Receive(host.ws, &env); err != nil {
			return
		}
		if env.Type == "ping" {
			host.send <- Envelope{Type: "pong", SessionID: sess.ID, SenderID: "server"}
			continue
		}
		switch env.Type {
		case "term_data":
			s.broadcast(sess, env, host.ID)
		case "control":
			s.applyControl(sess, env)
		case "forward_ack", "forward_data", "forward_close":
			s.sendToGuest(sess, env.TargetID, env)
		default:
			// ignore unknowns
		}
	}
}

func (s *Server) listenGuest(sess *sessionState, guest *peerConn) {
	defer s.disconnectGuest(sess.ID, guest.ID)
	for {
		var env Envelope
		if err := websocket.JSON.Receive(guest.ws, &env); err != nil {
			return
		}
		if env.Type == "ping" {
			guest.send <- Envelope{Type: "pong", SessionID: sess.ID, SenderID: "server"}
			continue
		}
		switch env.Type {
		case "term_input":
			if s.isWriteAllowed(sess, guest.ID) {
				env.SenderID = guest.ID
				sess.Host.send <- env
			}
		case "forward_init", "forward_data", "forward_close":
			env.SenderID = guest.ID
			sess.Host.send <- env
		default:
			// ignore
		}
	}
}

func (s *Server) broadcast(sess *sessionState, env Envelope, from string) {
	// fan out to guests (optionally a specific target)
	for id, g := range sess.Guests {
		if id == from {
			continue
		}
		if env.TargetID != "" && env.TargetID != id {
			continue
		}
		select {
		case g.send <- env:
		default:
		}
	}
}

func (s *Server) applyControl(sess *sessionState, env Envelope) {
	var c Control
	if err := json.Unmarshal(env.Payload, &c); err != nil {
		return
	}
	target := c.Target
	if target == "" || target == "*" || target == "all" {
		sess.AllowWriteAll = c.Allow
		for id := range sess.Guests {
			sess.WriteOverrides[id] = c.Allow
		}
		// broadcast to all guests
		for _, g := range sess.Guests {
			g.send <- env
		}
	} else {
		sess.WriteOverrides[target] = c.Allow
		if g, ok := sess.Guests[target]; ok {
			g.send <- env
		}
	}
}

func (s *Server) sendToGuest(sess *sessionState, targetID string, env Envelope) {
	if targetID == "" {
		return
	}
	if g, ok := sess.Guests[targetID]; ok {
		select {
		case g.send <- env:
		default:
		}
	}
}

func (s *Server) isWriteAllowed(sess *sessionState, guestID string) bool {
	if allowed, ok := sess.WriteOverrides[guestID]; ok {
		return allowed
	}
	return sess.AllowWriteAll
}

func (s *Server) disconnectGuest(sessionID, guestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	if guest, ok := sess.Guests[guestID]; ok {
		close(guest.send)
		guest.ws.Close()
		delete(sess.Guests, guestID)
		if sess.Host != nil {
			sess.Host.send <- Envelope{
				Type:      "guest_left",
				SessionID: sessionID,
				SenderID:  guestID,
				Payload:   mustJSON(GuestLeft{UserID: guestID}),
			}
		}
	}
	if len(sess.Guests) == 0 && sess.Host == nil {
		delete(s.sessions, sessionID)
	}
}

func (s *Server) dropSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	// notify guests the host is gone
	for _, g := range sess.Guests {
		select {
		case g.send <- Envelope{Type: "host_left", SessionID: sessionID, SenderID: "server"}:
		default:
		}
	}
	for _, g := range sess.Guests {
		close(g.send)
		_ = g.ws.Close()
	}
	if sess.Host != nil {
		close(sess.Host.send)
		_ = sess.Host.ws.Close()
	}
	delete(s.sessions, sessionID)
}

func (p *peerConn) writePump() {
	for msg := range p.send {
		_ = websocket.JSON.Send(p.ws, msg)
	}
}

func mustJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal: %v", err))
	}
	return data
}
