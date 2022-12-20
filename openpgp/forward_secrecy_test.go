package openpgp

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestForwardSecrecy(t *testing.T) {
	var config *packet.Config = new(packet.Config)

	config.ForwardSecrecy = true
	config.ForwardSecrets = 1
	config.ForwardSecretLifetimeSecs = 604800

	if config.ForwardSecrecy != true {
		t.Error("ForwardSecrecy:", config.ForwardSecrecy)
		return
	}
	if config.ForwardSecrets != 1 {
		t.Errorf("ForwardSecrets: %d", config.ForwardSecrets)
		return
	}
	if config.ForwardSecretLifetimeSecs != 604800 {
		t.Errorf("ForwardSecretLifetimeSecs: %d", config.ForwardSecretLifetimeSecs)
		return
	}

	// Example protocol run with ForwardSecrecy enabled
	alice, err := NewEntity("Alice", "alice", "alice@example.com", config)
	if err != nil {
		t.Errorf("Failed to create entity for Alice: %s", err)
		return
	}
	alice.AddForwardSecret(config)

	// Check if ForwardSecrecy is enabled for Subkey.
	indOTK := len(alice.Subkeys) - 1
	if alice.Subkeys[indOTK].Sig.FlagForwardSecrecy != true {
		t.Errorf("Alice: No one-time encryption key available!")
	}
}
