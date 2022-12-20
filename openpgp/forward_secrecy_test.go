package openpgp

import (
	"bytes"
	"io"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// `TestForwardSecrecy` checks if ForwardSecrecy is enabled correctly.
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
	alice, err := NewEntity("Alice", "sender", "alice@example.com", config)
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

// `TestEncryptionWithForwardSecrecy` is an example protocol run with ForwardSecrecy enabled,
// where Alice sends several encrypted messages to Bob, until his forward secrets are
// exhausted at which point their communication falls back as if ForwardSecrecy is not enabled.
func TestEncryptionWithForwardSecrecy(t *testing.T) {
	var config *packet.Config = new(packet.Config)

	config.ForwardSecrecy = true
	config.ForwardSecrets = 1
	config.ForwardSecretLifetimeSecs = 604800

	// Example protocol run with ForwardSecrecy enabled
	alice, err := NewEntity("Alice", "sender", "alice@example.com", config)
	if err != nil {
		t.Errorf("Failed to create entity for Alice: %s", err)
		return
	}

	numOTKs_alice := int(config.NumForwardSecrets())
	for i := 0; i < numOTKs_alice; i++ {
		alice.AddForwardSecret(config)
	}

	// Check if ForwardSecrecy is enabled for Subkey.
	for i := 1; i < numOTKs_alice+1; i++ {
		if alice.Subkeys[i].Sig.FlagForwardSecrecy != true {
			t.Errorf("Alice: No one-time encryption key available!")
		}
	}

	var config2 = new(packet.Config)

	config2.ForwardSecrecy = true
	config2.ForwardSecrets = 3
	config2.ForwardSecretLifetimeSecs = 604800

	bob, err := NewEntity("Bob", "recipient", "bob@example.com", config2)
	if err != nil {
		t.Errorf("failed to create entity for Bob: %s", err)
		return
	}

	if config2.ForwardSecrets != 3 {
		t.Errorf("ForwardSecrets: %d", config2.ForwardSecrets)
		return
	}

	if len(alice.Subkeys) != 1+numOTKs_alice {
		t.Errorf("Number of Alice' valid subkeys (after use): %d", len(alice.Subkeys))
	}

	numOTKs_bob := int(config2.NumForwardSecrets())
	for i := 0; i < numOTKs_bob; i++ {
		bob.AddForwardSecret(config2)
	}
	if len(bob.Subkeys) != 1+numOTKs_bob {
		t.Errorf("Number of Bob' valid subkeys: %d", len(bob.Subkeys))
	}

	// Check if ForwardSecrecy is enabled for Subkeys.
	for i := 1; i < numOTKs_bob+1; i++ {
		if bob.Subkeys[i].Sig.FlagForwardSecrecy != true {
			t.Errorf("Bob: Not enough one-time encryption keys available!")
		}
	}

	hints := FileHints{
		IsBinary: mathrand.Intn(2) == 0,
		FileName: string("filename"),
		ModTime:  time.Now(),
	}
	message := "Forward secrecy in action"

	var receivers []*Entity
	receivers = append(receivers, bob)

	// Encrypt message using a one-time key
	passphrase := "pa$$w0rd"
	err = alice.PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Fatalf("Error decrypting private key: %s", err)
	}

	buf := new(bytes.Buffer)
	w, err := Encrypt(buf, receivers, alice, &hints, config)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	// Decrypt message using the one-time key
	var keyring EntityList
	keyring = append(keyring, bob, alice)
	recoveredPlaintext, err := ReadMessage(buf, keyring, nil, nil)

	if err != nil {
		t.Fatalf("Error in ReadMessage: %s", err)
	}

	err = receivers[0].PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Errorf("Prompt: error decrypting key: %s", err)
	}

	recoveredMessage := ""
	body_reader := recoveredPlaintext.UnverifiedBody
	buffer := make([]byte, 1024)
	io.ReadFull(body_reader, buffer)
	recoveredMessage = strings.Trim(string(buffer[:]), string(rune(0x00)))

	if message != recoveredMessage {
		t.Fatalf("Error recovering messages: %s", err)
	}

	// Check if used one-time key has been deleted
	if len(bob.Subkeys) != numOTKs_bob {
		t.Errorf("Number of Bob' valid subkeys: %d", len(bob.Subkeys))
	}

	w, err = Encrypt(buf, receivers, alice, &hints, config)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	recoveredPlaintext, err = ReadMessage(buf, keyring, nil, nil)

	if err != nil {
		t.Fatalf("Error in ReadMessage: %s", err)
	}

	err = receivers[0].PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Errorf("Prompt: error decrypting key: %s", err)
	}

	recoveredMessage = ""
	body_reader = recoveredPlaintext.UnverifiedBody
	buffer = make([]byte, 1024)
	io.ReadFull(body_reader, buffer)
	recoveredMessage = strings.Trim(string(buffer[:]), string(rune(0x00)))

	if message != recoveredMessage {
		t.Fatalf("Error recovering messages: %s", err)
	}

	// Check if used one-time key has been deleted
	if len(bob.Subkeys) != 2 {
		t.Errorf("Number of Bob' valid subkeys: %d", len(bob.Subkeys))
	}

	w, err = Encrypt(buf, receivers, alice, &hints, config)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	recoveredPlaintext, err = ReadMessage(buf, keyring, nil, nil)

	if err != nil {
		t.Fatalf("Error in ReadMessage: %s", err)
	}

	err = receivers[0].PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Errorf("Prompt: error decrypting key: %s", err)
	}

	recoveredMessage = ""
	body_reader = recoveredPlaintext.UnverifiedBody
	buffer = make([]byte, 1024)
	io.ReadFull(body_reader, buffer)
	recoveredMessage = strings.Trim(string(buffer[:]), string(rune(0x00)))

	if message != recoveredMessage {
		t.Fatalf("Error recovering messages: %s", err)
	}

	// Check if used one-time key has been deleted
	if len(bob.Subkeys) != 1 {
		t.Errorf("Number of Bob' valid subkeys: %d", len(bob.Subkeys))
	}

	w, err = Encrypt(buf, receivers, alice, &hints, config)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	recoveredPlaintext, err = ReadMessage(buf, keyring, nil, nil)

	if err != nil {
		t.Fatalf("Error in ReadMessage: %s", err)
	}

	err = receivers[0].PrivateKey.Decrypt([]byte(passphrase))
	if err != nil {
		t.Errorf("Prompt: error decrypting key: %s", err)
	}

	recoveredMessage = ""
	body_reader = recoveredPlaintext.UnverifiedBody
	buffer = make([]byte, 1024)
	io.ReadFull(body_reader, buffer)
	recoveredMessage = strings.Trim(string(buffer[:]), string(rune(0x00)))

	if message != recoveredMessage {
		t.Fatalf("Error recovering messages: %s", err)
	}
	// Check only primary key is left and has not been deleted

	if len(bob.Subkeys) != 1 {
		t.Errorf("Number of Bob' valid subkeys: %d", len(bob.Subkeys))
	}
}
