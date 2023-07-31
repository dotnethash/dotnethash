package dotnethash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	math "math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength        = 16
	requestedLength   = 32
	formatMarker      = 0x01
	includeHeaderInfo = true
	iterCount         = 10000
	letterBytes       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	wordLength        = 32
)

type Hasher struct{}

func NewHasher() *Hasher {
	return &Hasher{}
}

func (h *Hasher) SecurityStamp() string {
	math.Seed(time.Now().UnixNano())

	word := make([]byte, wordLength)
	for i := 0; i < wordLength; i++ {
		word[i] = letterBytes[math.Intn(len(letterBytes))]
	}

	return string(word)
}

func (h *Hasher) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	subkey := pbkdf2.Key([]byte(password), salt, iterCount, requestedLength, sha256.New)

	var headerByteLength = 1
	if includeHeaderInfo {
		headerByteLength = 13
	}

	outputBytes := make([]byte, headerByteLength+saltLength+len(subkey))
	outputBytes[0] = formatMarker

	if includeHeaderInfo {
		writeNetworkByteOrder(outputBytes, 1, uint32(1))
		writeNetworkByteOrder(outputBytes, 5, uint32(iterCount))
		writeNetworkByteOrder(outputBytes, 9, uint32(saltLength))
	}

	copy(outputBytes[headerByteLength:], salt)
	copy(outputBytes[headerByteLength+saltLength:], subkey)

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
	if formatMarker != verifyMarker {
		return false
	}

	if includeHeaderInfo {
		shaUInt := readNetworkByteOrder(decodedHashedPassword, 1)
		if shaUInt != 1 {
			return false
		}

		iterCountRead := readNetworkByteOrder(decodedHashedPassword, 5)
		if iterCount != int(iterCountRead) {
			return false
		}

		saltLengthRead := readNetworkByteOrder(decodedHashedPassword, 9)
		if saltLength != int(saltLengthRead) {
			return false
		}
	}

	headerByteLength := 1
	if includeHeaderInfo {
		headerByteLength = 13
	}

	salt := decodedHashedPassword[headerByteLength : headerByteLength+saltLength]
	subkeyLength := len(decodedHashedPassword) - headerByteLength - saltLength

	if requestedLength != subkeyLength {
		return false
	}

	expectedSubkey := decodedHashedPassword[headerByteLength+saltLength:]

	actualSubkey := pbkdf2.Key([]byte(enteredPassword), salt, iterCount, subkeyLength, sha256.New)

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
