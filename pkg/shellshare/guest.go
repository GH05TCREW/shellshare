package shellshare

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"shellshare/internal/websocket"
	"shellshare/pkg/config"
	"shellshare/pkg/ids"
	"shellshare/pkg/secure"
	"shellshare/pkg/signaling"
)

// JoinSession connects to an existing session and streams output to stdout.
func JoinSession(ctx context.Context, cfg config.Config, sessionID, userID string) error {
	if userID == "" {
		userID = ids.UserID("guest")
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	keyPair, err := secure.GenerateKeyPair()
	if err != nil {
		return err
	}
	conn, err := websocket.Dial(cfg.SignalingURL, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("connect signaling: %w", err)
	}
	defer conn.Close()

	guest := &guestRuntime{
		cfg:           cfg,
		sessionID:     sessionID,
		userID:        userID,
		keyPair:       keyPair,
		conn:          conn,
		outgoing:      make(chan signaling.Envelope, 16),
		sessionCtx:    sessionCtx,
		sessionCancel: sessionCancel,
		forwardListen: cfg.ForwardListen,
		tunnels:       make(map[string]net.Conn),
		tunnelAck:     make(map[string]chan signaling.ForwardAck),
	}
	if err := guest.handshake(); err != nil {
		return err
	}
	if guest.directAddr != "" {
		guest.tryDirect()
	}

	fmt.Printf("Connected to %s (host %s)\n", sessionID, guest.hostName)
	fmt.Printf("Fingerprint: %s\n", secure.Fingerprint(guest.hostKey))
	if guest.allowWrite {
		fmt.Println("You can type. Ctrl+C to leave.")
	} else {
		fmt.Println("Read-only mode. Waiting for host to grant write access.")
	}

	go guest.writePump()
	go guest.readPump()
	if guest.allowWrite {
		guest.startInputPump(sessionCtx)
	}
	if guest.forwardListen != "" {
		go guest.startForwardListener()
	}

	// Block until context is done.
	<-sessionCtx.Done()
	return nil
}

type guestRuntime struct {
	cfg           config.Config
	sessionID     string
	userID        string
	keyPair       *secure.KeyPair
	conn          *websocket.Conn
	outgoing      chan signaling.Envelope
	hostKey       []byte
	sharedKey     []byte
	allowWrite    bool
	hostName      string
	inputCancel   context.CancelFunc
	sessionCtx    context.Context
	sessionCancel context.CancelFunc
	forwardListen string
	tunnels       map[string]net.Conn
	tunnelAck     map[string]chan signaling.ForwardAck
	mu            sync.Mutex
	directAddr    string
	directConn    net.Conn
}

func (g *guestRuntime) handshake() error {
	req := signaling.Envelope{
		Type:      "join",
		SessionID: g.sessionID,
		SenderID:  g.userID,
		Payload: mustJSON(signaling.Join{
			PublicKey: secure.EncodeKey(g.keyPair.Public),
			Name:      g.userID,
		}),
	}
	if err := websocket.JSON.Send(g.conn, req); err != nil {
		return err
	}
	var offer signaling.Envelope
	if err := websocket.JSON.Receive(g.conn, &offer); err != nil {
		return err
	}
	if offer.Type != "host_offer" {
		return fmt.Errorf("unexpected response: %s", offer.Type)
	}
	var body signaling.HostOffer
	if err := json.Unmarshal(offer.Payload, &body); err != nil {
		return err
	}
	hostKey, err := secure.DecodeKey(body.PublicKey)
	if err != nil {
		return err
	}
	shared, err := secure.ComputeShared(g.keyPair.Private, hostKey)
	if err != nil {
		return err
	}
	g.hostKey = hostKey
	g.sharedKey = shared
	g.allowWrite = body.AllowWrite
	g.hostName = body.Name
	g.directAddr = body.DirectAddr
	return nil
}

func (g *guestRuntime) inputPump(ctx context.Context) {
	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			data := make([]byte, 1024)
			n, err := reader.Read(data)
			if n > 0 {
				g.sendInput(data[:n])
			}
			if err != nil {
				return
			}
		}
	}
}

func (g *guestRuntime) startInputPump(ctx context.Context) {
	if g.inputCancel != nil {
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	g.inputCancel = cancel
	go g.inputPump(cctx)
}

func (g *guestRuntime) stopInputPump() {
	if g.inputCancel != nil {
		g.inputCancel()
		g.inputCancel = nil
	}
}

func (g *guestRuntime) sendInput(data []byte) {
	sealed, err := secure.Encrypt(g.sharedKey, data)
	if err != nil {
		return
	}
	g.sendEnvelope(signaling.Envelope{
		Type:      "term_input",
		SessionID: g.sessionID,
		SenderID:  g.userID,
		Payload: mustJSON(signaling.TermInput{
			Data:      base64.StdEncoding.EncodeToString(sealed),
			Timestamp: time.Now().Unix(),
		}),
	})
}

func (g *guestRuntime) readPump() {
	go g.heartbeat()
	for {
		var env signaling.Envelope
		if err := websocket.JSON.Receive(g.conn, &env); err != nil {
			g.sessionCancel()
			return
		}
		switch env.Type {
		case "term_data":
			var data signaling.TermData
			if json.Unmarshal(env.Payload, &data) != nil {
				continue
			}
			cipher, err := base64.StdEncoding.DecodeString(data.Data)
			if err != nil {
				continue
			}
			plain, err := secure.Decrypt(g.sharedKey, cipher)
			if err != nil {
				continue
			}
			os.Stdout.Write(plain)
		case "control":
			var c signaling.Control
			if json.Unmarshal(env.Payload, &c) == nil {
				g.allowWrite = c.Allow
				if g.allowWrite {
					fmt.Println("\n[write access granted]")
					g.startInputPump(g.sessionCtx)
				} else {
					fmt.Println("\n[write access revoked]")
					g.stopInputPump()
				}
			}
		case "host_left":
			fmt.Println("\n[host ended session]")
			g.sessionCancel()
			return
		case "ping":
			g.outgoing <- signaling.Envelope{
				Type:      "pong",
				SessionID: g.sessionID,
				SenderID:  g.userID,
			}
		case "forward_ack":
			g.handleForwardAck(env.Payload)
		case "forward_data":
			g.handleForwardData(env.Payload)
		case "forward_close":
			g.handleForwardClose(env.Payload)
		}
	}
}

func (g *guestRuntime) writePump() {
	for env := range g.outgoing {
		_ = websocket.JSON.Send(g.conn, env)
	}
}

func (g *guestRuntime) sendEnvelope(env signaling.Envelope) {
	g.mu.Lock()
	dc := g.directConn
	g.mu.Unlock()
	if dc != nil {
		writeEnvelope(dc, env)
		return
	}
	g.outgoing <- env
}

func (g *guestRuntime) heartbeat() {
	t := time.NewTicker(20 * time.Second)
	for {
		select {
		case <-g.sessionCtx.Done():
			return
		case <-t.C:
			g.outgoing <- signaling.Envelope{
				Type:      "ping",
				SessionID: g.sessionID,
				SenderID:  g.userID,
			}
		}
	}
}

// direct P2P support
func (g *guestRuntime) tryDirect() {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", g.directAddr)
	if err != nil {
		return
	}
	hello := signaling.Envelope{Type: "hello", SessionID: g.sessionID, SenderID: g.userID}
	if err := writeEnvelope(conn, hello); err != nil {
		conn.Close()
		return
	}
	g.mu.Lock()
	g.directConn = conn
	g.mu.Unlock()
	go g.readDirect(conn)
}

func (g *guestRuntime) readDirect(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var env signaling.Envelope
		if json.Unmarshal(sc.Bytes(), &env) != nil {
			continue
		}
		switch env.Type {
		case "term_data":
			var data signaling.TermData
			if json.Unmarshal(env.Payload, &data) != nil {
				continue
			}
			cipher, err := base64.StdEncoding.DecodeString(data.Data)
			if err != nil {
				continue
			}
			plain, err := secure.Decrypt(g.sharedKey, cipher)
			if err != nil {
				continue
			}
			os.Stdout.Write(plain)
		case "forward_ack":
			g.handleForwardAck(env.Payload)
		case "forward_data":
			g.handleForwardData(env.Payload)
		case "forward_close":
			g.handleForwardClose(env.Payload)
		}
	}
	g.mu.Lock()
	g.directConn = nil
	g.mu.Unlock()
	conn.Close()
}

// forwarding (guest side)
func (g *guestRuntime) startForwardListener() {
	ln, err := net.Listen("tcp", g.forwardListen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forward listen error: %v\n", err)
		return
	}
	fmt.Printf("Forwarding host service to %s\n", g.forwardListen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if g.sessionCtx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "forward accept error: %v\n", err)
			continue
		}
		tunnelID := ids.SessionID()
		g.registerTunnel(tunnelID, conn)
		g.sendEnvelope(signaling.Envelope{
			Type:      "forward_init",
			SessionID: g.sessionID,
			SenderID:  g.userID,
			Payload:   mustJSON(signaling.ForwardInit{TunnelID: tunnelID}),
		})
		go g.awaitForwardAck(tunnelID, conn)
	}
}

func (g *guestRuntime) registerTunnel(id string, conn net.Conn) {
	g.mu.Lock()
	g.tunnels[id] = conn
	g.tunnelAck[id] = make(chan signaling.ForwardAck, 1)
	g.mu.Unlock()
}

func (g *guestRuntime) awaitForwardAck(tunnelID string, conn net.Conn) {
	ackCh := g.getAckChan(tunnelID)
	if ackCh == nil {
		conn.Close()
		return
	}
	select {
	case ack := <-ackCh:
		if !ack.Accepted {
			fmt.Fprintf(os.Stderr, "forward rejected: %s\n", ack.Error)
			g.closeTunnel(tunnelID)
			return
		}
		go g.pipeLocalToHost(tunnelID, conn)
	case <-time.After(5 * time.Second):
		fmt.Fprintf(os.Stderr, "forward timeout\n")
		g.closeTunnel(tunnelID)
	case <-g.sessionCtx.Done():
		g.closeTunnel(tunnelID)
	}
}

func (g *guestRuntime) pipeLocalToHost(tunnelID string, conn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			payload := signaling.ForwardData{
				TunnelID: tunnelID,
				Data:     base64.StdEncoding.EncodeToString(buf[:n]),
			}
			g.sendEnvelope(signaling.Envelope{
				Type:      "forward_data",
				SessionID: g.sessionID,
				SenderID:  g.userID,
				Payload:   mustJSON(payload),
			})
		}
		if err != nil {
			g.sendEnvelope(signaling.Envelope{
				Type:      "forward_close",
				SessionID: g.sessionID,
				SenderID:  g.userID,
				Payload:   mustJSON(signaling.ForwardClose{TunnelID: tunnelID, Reason: err.Error()}),
			})
			g.closeTunnel(tunnelID)
			return
		}
	}
}

func (g *guestRuntime) handleForwardAck(payload json.RawMessage) {
	var ack signaling.ForwardAck
	if err := json.Unmarshal(payload, &ack); err != nil {
		return
	}
	g.mu.Lock()
	ch, ok := g.tunnelAck[ack.TunnelID]
	g.mu.Unlock()
	if ok {
		ch <- ack
	}
}

func (g *guestRuntime) handleForwardData(payload json.RawMessage) {
	var data signaling.ForwardData
	if err := json.Unmarshal(payload, &data); err != nil {
		return
	}
	g.mu.Lock()
	conn, ok := g.tunnels[data.TunnelID]
	g.mu.Unlock()
	if !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		return
	}
	_, err = conn.Write(raw)
	if err != nil {
		g.closeTunnel(data.TunnelID)
	}
}

func (g *guestRuntime) handleForwardClose(payload json.RawMessage) {
	var c signaling.ForwardClose
	if err := json.Unmarshal(payload, &c); err != nil {
		return
	}
	g.closeTunnel(c.TunnelID)
}

func (g *guestRuntime) closeTunnel(tunnelID string) {
	g.mu.Lock()
	if c, ok := g.tunnels[tunnelID]; ok {
		c.Close()
		delete(g.tunnels, tunnelID)
	}
	if ch, ok := g.tunnelAck[tunnelID]; ok {
		close(ch)
		delete(g.tunnelAck, tunnelID)
	}
	g.mu.Unlock()
}

func (g *guestRuntime) getAckChan(tunnelID string) chan signaling.ForwardAck {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tunnelAck[tunnelID]
}
