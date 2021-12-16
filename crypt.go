// Package crypt provides simple functions to encrypt and decrypt.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

var globalPassword string
var tempSignKey = RandomAlphanumeric(30)

const saltLen = 18

func HashPassword(pwd string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pwd), 12)
	if err != nil {
		// this should only happen if the factor is invalid, but we know it is ok
		panic(err)
	}
	return string(h)
}

func CheckHashPasword(hash, pwd string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd)) == nil
}

// Encrypts encrypts the text.
func Encrypts(text, password string) (string, error) {
	e, err := Encrypt([]byte(text), []byte(password))
	if err != nil {
		return "", err
	}

	encoder := base64.StdEncoding.WithPadding(base64.NoPadding)
	return encoder.EncodeToString(e), nil
}

// Decrypts decrypts the text.
func Decrypts(text, password string) (string, error) {
	encoder := base64.StdEncoding.WithPadding(base64.NoPadding)
	e, err := encoder.DecodeString(text)
	if err != nil {
		return "", err
	}

	d, err := Decrypt(e, []byte(password))
	if err != nil {
		return "", err
	}

	return string(d), err
}

func EncryptTripleDESCBC(decrypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	blockMode := cipher.NewCBCEncrypter(block, iv)

	decrypted = ZeroPadding(decrypted, block.BlockSize())
	encrypted := make([]byte, len(decrypted))
	blockMode.CryptBlocks(encrypted, decrypted)
	return encrypted, nil
}

func DecryptTripleDESCBC(encrypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	decrypted = ZeroUnPadding(decrypted)
	return decrypted, nil
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

// Encrypts encrypts the text.
func Encrypt(plaintext, password []byte) ([]byte, error) {
	key, salt := generateFromPassword(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return append(salt, gcm.Seal(nonce, nonce, plaintext, nil)...), nil
}

// Decrypts decrypts the text.
func Decrypt(ciphertext, password []byte) ([]byte, error) {
	salt, c, err := decode(ciphertext)
	if err != nil {
		return nil, err
	}

	key := generateFromPasswordAndSalt(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, c[:gcm.NonceSize()], c[gcm.NonceSize():], nil)
}

// decode returns the salt and cipertext
func decode(ciphertext []byte) ([]byte, []byte, error) {
	return ciphertext[:saltLen], ciphertext[saltLen:], nil
}

func generateFromPasswordAndSalt(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 4096, 32, sha1.New)
}

// generateFromPassword returns the key and the salt.
//
// https://github.com/golang/crypto/blob/master/pbkdf2/pbkdf2.go
//
// dk := pbkdf2.Key([]byte("some password"), salt, 4096, 32, sha1.New)
//
func generateFromPassword(password []byte) ([]byte, []byte) {
	salt := Random(saltLen)
	dk := pbkdf2.Key(password, salt, 4096, 32, sha1.New)
	return dk, salt
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func RandomAlphanumeric(size int) string {
	dictionary := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	l := byte(len(dictionary))
	var b = make([]byte, size)
	rand.Read(b)
	for k, v := range b {
		b[k] = dictionary[v%l]
	}
	return string(b)
}
