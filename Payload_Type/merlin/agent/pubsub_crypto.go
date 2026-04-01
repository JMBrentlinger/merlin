package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("[Merlin] [pubsub_crypto.go] pkcs7Unpad: empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] pkcs7Unpad: invalid padding value %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("[Merlin] [pubsub_crypto.go] pkcs7Unpad: invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] key must be 32 bytes, got %d", len(key))
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)

	ivAndCiphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ivAndCiphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] failed to generate IV: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] failed to create cipher: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ivAndCiphertext[aes.BlockSize:], padded)

	mac := hmac.New(sha256.New, key)
	mac.Write(ivAndCiphertext)
	hmacSum := mac.Sum(nil)

	// Return: IV[16] + ciphertext + HMAC[32]
	return append(ivAndCiphertext, hmacSum...), nil
}

func aesDecrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] key must be 32 bytes, got %d", len(key))
	}
	if len(data) < aes.BlockSize+aes.BlockSize+32 {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] data too short (%d bytes)", len(data))
	}

	iv := data[:aes.BlockSize]
	hmacReceived := data[len(data)-32:]
	ciphertext := data[aes.BlockSize : len(data)-32]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] ciphertext length %d is not a multiple of block size", len(ciphertext))
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(ciphertext)
	hmacComputed := mac.Sum(nil)

	if !hmac.Equal(hmacReceived, hmacComputed) {
		return nil, errors.New("[Merlin] [pubsub_crypto.go] HMAC verification failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] failed to create cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func buildMythicFrame(uuidStr string, body []byte) string {
	raw := make([]byte, 0, len(uuidStr)+len(body))
	raw = append(raw, []byte(uuidStr)...)
	raw = append(raw, body...)
	return base64.StdEncoding.EncodeToString(raw)
}

func parseMythicFrame(base64Msg string) (string, []byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Msg)
	if err != nil {
		return "", nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] base64 decode failed: %w", err)
	}
	if len(decoded) < 36 {
		return "", nil, fmt.Errorf("[Merlin] [pubsub_crypto.go] message too short (%d bytes)", len(decoded))
	}
	uuidStr := string(decoded[:36])
	body := decoded[36:]
	return uuidStr, body, nil
}
