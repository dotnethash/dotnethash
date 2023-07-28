package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	_saltLength        = 16
	_requestedLength   = 32
	_formatMarker      = 0x01
	_includeHeaderInfo = true
	_iterCount         = 10000
)

type Hasher struct{}

func NewHasher() *Hasher {
	return &Hasher{}
}

func (h *Hasher) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	salt := make([]byte, _saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	subkey := pbkdf2.Key([]byte(password), salt, _iterCount, _requestedLength, sha256.New)

	var headerByteLength = 1
	if _includeHeaderInfo {
		headerByteLength = 13
	}

	outputBytes := make([]byte, headerByteLength+_saltLength+len(subkey))
	outputBytes[0] = _formatMarker

	if _includeHeaderInfo {
		writeNetworkByteOrder(outputBytes, 1, uint32(1))
		writeNetworkByteOrder(outputBytes, 5, uint32(_iterCount))
		writeNetworkByteOrder(outputBytes, 9, uint32(_saltLength))
	}

	copy(outputBytes[headerByteLength:], salt)
	copy(outputBytes[headerByteLength+_saltLength:], subkey)

	return base64.StdEncoding.EncodeToString(outputBytes), nil
}

func (h *Hasher) VerifyPassword(hashedPassword, enteredPassword string) bool {
	if enteredPassword == "" || hashedPassword == "" {
		return false
	}

	decodedHashedPassword, err := base64.StdEncoding.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	if len(decodedHashedPassword) == 0 {
		return false
	}

	verifyMarker := decodedHashedPassword[0]
	if _formatMarker != verifyMarker {
		return false
	}

	if _includeHeaderInfo {
		shaUInt := readNetworkByteOrder(decodedHashedPassword, 1)
		if shaUInt != 1 {
			return false
		}

		iterCountRead := readNetworkByteOrder(decodedHashedPassword, 5)
		if _iterCount != int(iterCountRead) {
			return false
		}

		saltLengthRead := readNetworkByteOrder(decodedHashedPassword, 9)
		if _saltLength != int(saltLengthRead) {
			return false
		}
	}

	headerByteLength := 1
	if _includeHeaderInfo {
		headerByteLength = 13
	}

	salt := decodedHashedPassword[headerByteLength : headerByteLength+_saltLength]
	subkeyLength := len(decodedHashedPassword) - headerByteLength - _saltLength

	if _requestedLength != subkeyLength {
		return false
	}

	expectedSubkey := decodedHashedPassword[headerByteLength+_saltLength:]

	actualSubkey := pbkdf2.Key([]byte(enteredPassword), salt, _iterCount, subkeyLength, sha256.New)

	return byteArraysEqual(actualSubkey, expectedSubkey)
}

func readNetworkByteOrder(buf []byte, offset int) uint32 {
	return uint32(buf[offset])<<24 | uint32(buf[offset+1])<<16 | uint32(buf[offset+2])<<8 | uint32(buf[offset+3])
}

func writeNetworkByteOrder(buf []byte, offset int, value uint32) {
	buf[offset] = byte(value >> 24)
	buf[offset+1] = byte(value >> 16)
	buf[offset+2] = byte(value >> 8)
	buf[offset+3] = byte(value)
}

func byteArraysEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
