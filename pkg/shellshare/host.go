package shellshare

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"shellshare/internal/websocket"
	"shellshare/pkg/config"
	"shellshare/pkg/ids"
	"shellshare/pkg/secure"
	"shellshare/pkg/signaling"
	"shellshare/pkg/terminal"
)

// HostSession starts a broadcast session and shares the local shell output with guests.
func HostSession(ctx context.Context, cfg config.Config, sessionID string) error {
	if sessionID == "" {
		sessionID = ids.SessionID()
	}
	keyPair, err := secure.GenerateKeyPair()
	if err != nil {
		return err
	}

	conn, err := websocket.Dial(cfg.SignalingURL, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("connect signaling: %w", err)
	}
	defer conn.Close()

	host := &hostRuntime{
		cfg:         cfg,
		sessionID:   sessionID,
		keyPair:     keyPair,
		conn:        conn,
		guestKeys:   make(map[string][]byte),
		incoming:    make(chan []byte, 32),
		outgoing:    make(chan signaling.Envelope, 32),
		tunnels:     make(map[string]net.Conn),
		directConns: make(map[string]net.Conn),
	}
	host.forwardTarget = cfg.ForwardTarget
	if cfg.RecordPath != "" {
		f, err := os.Create(cfg.RecordPath)
		if err != nil {
			return fmt.Errorf("create record file: %w", err)
		}
		host.recordWriter = f
		fmt.Printf("Recording session to %s\n", cfg.RecordPath)
		defer f.Close()
	}
	defer host.closeAllTunnels()

	if err := host.startDirectListener(); err != nil {
		return err
	}

	if err := host.handshake(); err != nil {
		return err
	}

	fmt.Printf("Session ID: %s\n", sessionID)
	fmt.Printf("Join command: shellshare join %s --server %s\n", sessionID, cfg.SignalingURL)
	fmt.Printf("Fingerprint: %s\n", secure.Fingerprint(keyPair.Public))

	go host.writePump()
	go host.readPump()

	outWriter := io.MultiWriter(os.Stdout, host)
	runner := terminal.DefaultRunner()
	go host.captureHostInput(ctx)
	if err := runner.Start(ctx, outWriter, host.localInput, host.incoming); err != nil {
		return err
	}
	return nil
}

type hostRuntime struct {
	cfg       config.Config
	sessionID string
	keyPair   *secure.KeyPair
	conn      *websocket.Conn

	localInput    chan []byte
	guestKeys     map[string][]byte
	incoming      chan []byte
	outgoing      chan signaling.Envelope
	seq           int64
	mu            sync.Mutex
	forwardTarget string
	tunnels       map[string]net.Conn
	recordWriter  io.WriteCloser
	directLn      net.Listener
	directConns   map[string]net.Conn
	directAddr    string
}

// Write implements io.Writer so terminal output can be broadcast to guests.
func (h *hostRuntime) Write(p []byte) (int, error) {
	if h.recordWriter != nil {
		_, _ = h.recordWriter.Write(p)
	}
	
	h.mu.Lock()
	guestsCopy := make(map[string][]byte, len(h.guestKeys))
	for guestID, shared := range h.guestKeys {
		guestsCopy[guestID] = shared
	}
	h.mu.Unlock()
	
	for guestID, shared := range guestsCopy {
		sealed, err := secure.Encrypt(shared, p)
		if err != nil {
			continue
		}
		payload := signaling.TermData{
			Data:      base64.StdEncoding.EncodeToString(sealed),
			Sequence:  atomic.AddInt64(&h.seq, 1),
			Timestamp: time.Now().Unix(),
		}
		h.sendEnvelope(guestID, signaling.Envelope{
			Type:      "term_data",
			SessionID: h.sessionID,
			SenderID:  "host",
			TargetID:  guestID,
			Payload:   mustJSON(payload),
		})
	}
	return len(p), nil
}

func (h *hostRuntime) handshake() error {
	h.localInput = make(chan []byte, 32)
	announce := signaling.Announce{
		PublicKey:  secure.EncodeKey(h.keyPair.Public),
		AllowWrite: h.cfg.AllowWrite,
		ReadOnly:   h.cfg.ReadOnly,
		Name:       h.cfg.Name,
		DirectAddr: h.directAddr,
	}
	env := signaling.Envelope{
		Type:      "announce",
		SessionID: h.sessionID,
		Payload:   mustJSON(announce),
	}
	if err := websocket.JSON.Send(h.conn, env); err != nil {
		return err
	}
	var ack signaling.Envelope
	if err := websocket.JSON.Receive(h.conn, &ack); err != nil {
		return err
	}
	if ack.Type != "session_ready" {
		return fmt.Errorf("unexpected handshake response: %s", ack.Type)
	}
	return nil
}

func (h *hostRuntime) readPump() {
	go h.heartbeat()
	for {
		var env signaling.Envelope
		if err := websocket.JSON.Receive(h.conn, &env); err != nil {
			return
		}
		switch env.Type {
		case "guest_joined":
			var g signaling.GuestJoined
			if json.Unmarshal(env.Payload, &g) == nil {
				guestKey, err := secure.DecodeKey(g.PublicKey)
				if err == nil {
					if shared, err := secure.ComputeShared(h.keyPair.Private, guestKey); err == nil {
						h.mu.Lock()
						h.guestKeys[g.UserID] = shared
						h.mu.Unlock()
						if h.cfg.ShowJoinNotifications {
							fmt.Printf("[guest %s joined]\n", g.UserID)
						}
					}
				}
			}
		case "guest_left":
			var left signaling.GuestLeft
			if json.Unmarshal(env.Payload, &left) == nil {
				h.mu.Lock()
				delete(h.guestKeys, left.UserID)
				h.mu.Unlock()
				fmt.Printf("[guest %s left]\n", left.UserID)
			}
		case "term_input":
			guestID := env.SenderID
			h.mu.Lock()
			shared, ok := h.guestKeys[guestID]
			h.mu.Unlock()
			if !ok {
				continue
			}
			var input signaling.TermInput
			if err := json.Unmarshal(env.Payload, &input); err != nil {
				continue
			}
			cipher, err := base64.StdEncoding.DecodeString(input.Data)
			if err != nil {
				continue
			}
			plain, err := secure.Decrypt(shared, cipher)
			if err != nil {
				continue
			}
			h.incoming <- plain
		case "forward_init":
			h.handleForwardInit(env.SenderID, env.Payload)
		case "forward_data":
			h.handleForwardData(env.SenderID, env.Payload)
		case "forward_close":
			h.handleForwardClose(env.SenderID, env.Payload)
		case "pong":
			// keep-alive acknowledgement
		}
	}
}

func (h *hostRuntime) writePump() {
	for env := range h.outgoing {
		_ = websocket.JSON.Send(h.conn, env)
	}
}

func (h *hostRuntime) sendEnvelope(guestID string, env signaling.Envelope) {
	h.mu.Lock()
	direct := h.directConns[guestID]
	h.mu.Unlock()
	if direct != nil {
		writeEnvelope(direct, env)
		return
	}
	h.outgoing <- env
}

func (h *hostRuntime) captureHostInput(ctx context.Context) {
	reader := bufio.NewReader(os.Stdin)
	var cmdBuf []byte
	commandMode := false
	for {
		select {
		case <-ctx.Done():
			return
		default:
			b, err := reader.ReadByte()
			if err != nil {
				close(h.localInput)
				return
			}
			if !commandMode {
				if b == '/' {
					commandMode = true
					cmdBuf = append(cmdBuf, b)
					continue
				}
				h.localInput <- []byte{b}
				continue
			}
			// collecting a command line
			cmdBuf = append(cmdBuf, b)
			if b == '\n' || b == '\r' {
				line := strings.TrimSpace(string(cmdBuf))
				if !h.handleCommand(line) {
					h.localInput <- cmdBuf
				}
				cmdBuf = cmdBuf[:0]
				commandMode = false
			}
		}
	}
}

func (h *hostRuntime) handleCommand(line string) bool {
	if !strings.HasPrefix(line, "/") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return true
	}
	switch fields[0] {
	case "/grant":
		if len(fields) < 2 {
			fmt.Println("usage: /grant <user|*>")
			return true
		}
		h.sendControl(fields[1], true)
	case "/revoke":
		if len(fields) < 2 {
			fmt.Println("usage: /revoke <user|*>")
			return true
		}
		h.sendControl(fields[1], false)
	case "/who":
		h.mu.Lock()
		for id := range h.guestKeys {
			fmt.Printf("guest: %s\n", id)
		}
		h.mu.Unlock()
	case "/quit":
		fmt.Println("Ending session...")
		_ = h.conn.Close()
		os.Exit(0)
	default:
		fmt.Println("commands: /grant, /revoke, /who, /quit")
	}
	return true
}

func (h *hostRuntime) sendControl(target string, allow bool) {
	ctrl := signaling.Control{Action: "write", Target: target, Allow: allow}
	h.outgoing <- signaling.Envelope{
		Type:      "control",
		SessionID: h.sessionID,
		SenderID:  "host",
		TargetID:  target,
		Payload:   mustJSON(ctrl),
	}
}

func (h *hostRuntime) heartbeat() {
	t := time.NewTicker(20 * time.Second)
	for range t.C {
		h.outgoing <- signaling.Envelope{
			Type:      "ping",
			SessionID: h.sessionID,
			SenderID:  "host",
		}
	}
}

// direct P2P helpers
func (h *hostRuntime) startDirectListener() error {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	h.directLn = ln
	h.directAddr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.handleDirectConn(conn)
		}
	}()
	return nil
}

func (h *hostRuntime) handleDirectConn(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// first message must be a hello
	if !sc.Scan() {
		conn.Close()
		return
	}
	var hello signaling.Envelope
	if err := json.Unmarshal(sc.Bytes(), &hello); err != nil || hello.SessionID != h.sessionID {
		conn.Close()
		return
	}
	guestID := hello.SenderID
	h.mu.Lock()
	h.directConns[guestID] = conn
	h.mu.Unlock()
	for sc.Scan() {
		var env signaling.Envelope
		if err := json.Unmarshal(sc.Bytes(), &env); err != nil {
			continue
		}
		switch env.Type {
		case "term_input":
			guestID := env.SenderID
			h.mu.Lock()
			shared, ok := h.guestKeys[guestID]
			h.mu.Unlock()
			if !ok {
				continue
			}
			var input signaling.TermInput
			if err := json.Unmarshal(env.Payload, &input); err != nil {
				continue
			}
			cipher, err := base64.StdEncoding.DecodeString(input.Data)
			if err != nil {
				continue
			}
			plain, err := secure.Decrypt(shared, cipher)
			if err != nil {
				continue
			}
			h.incoming <- plain
		case "forward_init":
			h.handleForwardInit(env.SenderID, env.Payload)
		case "forward_data":
			h.handleForwardData(env.SenderID, env.Payload)
		case "forward_close":
			h.handleForwardClose(env.SenderID, env.Payload)
		}
	}
	h.mu.Lock()
	delete(h.directConns, guestID)
	h.mu.Unlock()
	conn.Close()
}

// forwarding handlers
func (h *hostRuntime) handleForwardInit(guestID string, payload json.RawMessage) {
	var init signaling.ForwardInit
	if err := json.Unmarshal(payload, &init); err != nil {
		return
	}
	if h.forwardTarget == "" {
		h.sendForwardAck(guestID, init.TunnelID, false, "forwarding not enabled")
		return
	}
	conn, err := net.Dial("tcp", h.forwardTarget)
	if err != nil {
		h.sendForwardAck(guestID, init.TunnelID, false, err.Error())
		return
	}
	h.mu.Lock()
	h.tunnels[init.TunnelID] = conn
	h.mu.Unlock()
	h.sendForwardAck(guestID, init.TunnelID, true, "")
	go h.pipeTargetToGuest(guestID, init.TunnelID, conn)
}

func (h *hostRuntime) handleForwardData(guestID string, payload json.RawMessage) {
	var data signaling.ForwardData
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	h.mu.Lock()
	conn, ok := h.tunnels[data.TunnelID]
	h.mu.Unlock()
	if !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		return
	}
	_, err = conn.Write(raw)
	if err != nil {
		h.closeTunnel(data.TunnelID)
		h.sendForwardClose(guestID, data.TunnelID, err.Error())
	}
}

func (h *hostRuntime) handleForwardClose(guestID string, payload json.RawMessage) {
	var c signaling.ForwardClose
	if err := json.Unmarshal(payload, &c); err != nil {
		return
	}
	h.closeTunnel(c.TunnelID)
}

func (h *hostRuntime) sendForwardAck(guestID, tunnelID string, ok bool, errMsg string) {
	ack := signaling.ForwardAck{TunnelID: tunnelID, Accepted: ok, Error: errMsg}
	h.sendEnvelope(guestID, signaling.Envelope{
		Type:      "forward_ack",
		SessionID: h.sessionID,
		SenderID:  "host",
		TargetID:  guestID,
		Payload:   mustJSON(ack),
	})
}

func (h *hostRuntime) sendForwardClose(guestID, tunnelID, reason string) {
	h.sendEnvelope(guestID, signaling.Envelope{
		Type:      "forward_close",
		SessionID: h.sessionID,
		SenderID:  "host",
		TargetID:  guestID,
		Payload:   mustJSON(signaling.ForwardClose{TunnelID: tunnelID, Reason: reason}),
	})
}

func (h *hostRuntime) pipeTargetToGuest(guestID, tunnelID string, conn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			payload := signaling.ForwardData{
				TunnelID: tunnelID,
				Data:     base64.StdEncoding.EncodeToString(buf[:n]),
			}
			h.sendEnvelope(guestID, signaling.Envelope{
				Type:      "forward_data",
				SessionID: h.sessionID,
				SenderID:  "host",
				TargetID:  guestID,
				Payload:   mustJSON(payload),
			})
		}
		if err != nil {
			h.closeTunnel(tunnelID)
			h.sendForwardClose(guestID, tunnelID, err.Error())
			return
		}
	}
}

func (h *hostRuntime) closeTunnel(tunnelID string) {
	h.mu.Lock()
	if conn, ok := h.tunnels[tunnelID]; ok {
		conn.Close()
		delete(h.tunnels, tunnelID)
	}
	h.mu.Unlock()
}

func (h *hostRuntime) closeAllTunnels() {
	h.mu.Lock()
	for id, conn := range h.tunnels {
		conn.Close()
		delete(h.tunnels, id)
	}
	for id, conn := range h.directConns {
		conn.Close()
		delete(h.directConns, id)
	}
	h.mu.Unlock()
	if h.directLn != nil {
		h.directLn.Close()
	}
}


