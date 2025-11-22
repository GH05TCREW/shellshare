# ShellShare

Terminal sharing with end-to-end encryption. Host a shell session, guests connect and view in real-time.

## Features

- End-to-end encryption (Curve25519 key exchange, AES-GCM)
- Direct P2P connections with relay fallback
- Read-only guests by default, host can grant write access
- Session recording to file
- Port forwarding through encrypted channel
- Cross-platform: Windows (ConPTY), Linux, macOS (PTY)
- Self-hosted signaling server
- Single static binary

## Installation

```bash
git clone https://github.com/GH05TCREW/shellshare
cd shellshare
go build -o shellshare cmd/shellshare/main.go
```

## Usage

### Start signaling server

```bash
shellshare serve --addr :7777
```

### Host a session

```bash
shellshare host --server ws://localhost:7777/ws
```

Prints session ID and join command. Session is read-only by default.

Options:
- `--allow-write` - Allow guests to type
- `--name <name>` - Set host name
- `--record <file>` - Record session to file
- `--forward-target <host:port>` - Expose local service to guests
- `--session <id>` - Use custom session ID

### Join a session

```bash
shellshare guest <session-id> --server ws://localhost:7777/ws
```

Options:
- `--user <name>` - Set guest name
- `--forward-listen <:port>` - Access host's forwarded service locally

### List sessions

```bash
shellshare list --server ws://localhost:7777/ws
```

### Host commands

Type these in the host terminal:
- `/grant <user|*>` - Grant write access
- `/revoke <user|*>` - Revoke write access
- `/who` - List connected guests
- `/quit` - End session

## Configuration

Optional `~/.shellshare/config.toml`:

```toml
[server]
signaling_url = "ws://localhost:7777/ws"

[security]
auto_approve_guests = false
fingerprint_verification = true
session_timeout = 3600

[display]
show_join_notifications = true
color_scheme = "auto"
```

Environment variables:
- `SHELLSHARE_SIGNALING_URL`
- `SHELLSHARE_NAME`
- `SHELLSHARE_ALLOW_WRITE`
- `SHELLSHARE_READ_ONLY`

## How it works

1. Host and guests connect to signaling server via WebSocket
2. Curve25519 key exchange establishes shared secret per guest
3. Host attempts direct TCP connection to each guest
4. Falls back to relay through signaling server if direct fails
5. Terminal data encrypted with AES-GCM before transmission
6. Server cannot decrypt traffic (end-to-end encryption)

## Port forwarding

Host exposes a local service:
```bash
shellshare host --forward-target localhost:8080
```

Guest accesses it:
```bash
shellshare guest <session-id> --forward-listen :8080
# Now localhost:8080 on guest connects to host's service
```

## Session recording

Host records all output:
```bash
shellshare host --record session.log
```

Replay:
```bash
cat session.log
```

## Security

- Each guest gets unique encryption key
- Signaling server only routes encrypted envelopes
- Fingerprint verification on connection
- Host controls write permissions per guest
- No plaintext transmission

## License

MIT

