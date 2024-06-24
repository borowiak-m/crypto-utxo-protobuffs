package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	// check the gen key is of default key len
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)
	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)
	// check successfull verification of same message
	assert.True(t, sig.Verify(pubKey, msg))
	// check failed verification of false message
	assert.False(t, sig.Verify(pubKey, []byte("foo")))
	// check failed verification with invalid pub key
	anotherPrivKey := GeneratePrivateKey()
	anotherPubKey := anotherPrivKey.Public()
	assert.False(t, sig.Verify(anotherPubKey, msg))
}
