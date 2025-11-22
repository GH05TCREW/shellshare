package ids

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var adjectives = []string{
	"cozy", "brisk", "bright", "calm", "curious", "eager", "gentle", "lively", "nimble", "quiet", "steady", "swift",
}

var nouns = []string{
	"tiger", "otter", "lynx", "falcon", "whale", "panther", "eagle", "sparrow", "orca", "fox", "badger", "hare",
}

// SessionID returns human friendly IDs like cozy-tiger-4829.
func SessionID() string {
	number := randomInt(9000) + 1000
	return fmt.Sprintf("%s-%s-%04d", adjectives[randomInt(len(adjectives))], nouns[randomInt(len(nouns))], number)
}

// UserID returns a stable prefix + random suffix for guests.
func UserID(prefix string) string {
	if prefix == "" {
		prefix = "guest"
	}
	return fmt.Sprintf("%s-%04d", prefix, randomInt(10000))
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}
