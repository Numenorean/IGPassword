package igencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Encrypt function
// rsaKey - RSA public key, keyID - RSA public key id
// First of all we generate AES key(and IV) it's like "session_key"
// then we encrypt that key with RSA encryption key provided in header ig-set-password-encryption-pub-key
// then we do AES-GCM Final with password, authTag is timestamp
// then we must create result which includes: 1, keyID, nonce, 0, 1, encrypted key, auth tag and ecnrypted password
func Encrypt(rsaKey, password []byte, keyID int) string {
	publicKey, _ := parseRsaPublicKeyFromPemStr(rsaKey)

	randKey := make([]byte, 32)
	io.ReadFull(rand.Reader, randKey)
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)

	encrypted, _ := rsa.EncryptPKCS1v15(rand.Reader, publicKey, randKey)

	block, _ := aes.NewCipher(randKey)
	aesgcm, _ := cipher.NewGCM(block)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	cipherText := aesgcm.Seal(nil, nonce, password, []byte(timestamp))
	authTag := cipherText[len(cipherText)-16:]
	cipherText = cipherText[:len(cipherText)-16]

	var result []byte
	result = append(result, []byte{1, byte(keyID)}...)
	result = append(result, nonce...)
	result = append(result, []byte{0, 1}...)
	result = append(result, encrypted...)
	result = append(result, authTag...)
	result = append(result, cipherText...)
	return fmt.Sprintf("#PWD_INSTAGRAM:4:%s:%s", timestamp, base64.StdEncoding.EncodeToString(result))
}

func parseRsaPublicKeyFromPemStr(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
