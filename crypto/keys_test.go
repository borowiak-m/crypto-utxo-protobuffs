package crypto

import (
	"fmt"
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

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "ff269fd461ecfef0b1596d98bd39097f255a85daf2d2338efc4fb577871a16ec"
		addressStr = "c8af054427cab9bb84536e97087b49d84f5164a8"
		privKey    = NewPrivateKeyFromString(seed)
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	addr := privKey.Public().Address()
	assert.Equal(t, addressStr, addr.String())

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

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
