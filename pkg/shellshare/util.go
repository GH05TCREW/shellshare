package shellshare

import (
	"encoding/json"
	"net"

	"shellshare/pkg/signaling"
)

// writeEnvelope writes a JSON-encoded envelope to a direct TCP connection.
func writeEnvelope(conn net.Conn, env signaling.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

// mustJSON marshals v to JSON, panicking on error (for initialization only).
func mustJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
