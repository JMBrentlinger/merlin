package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// generateRSAKeyPair generates a 4096-bit RSA key pair.
// Returns the private key and the PKCS1 DER-encoded public key bytes.
func generateRSAKeyPair() (*rsa.PrivateKey, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	pubKeyDER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	return privKey, pubKeyDER, nil
}

// rsaDecryptOAEP decrypts ciphertext using RSA OAEP with SHA1 (Mythic's default).
func rsaDecryptOAEP(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, ciphertext, nil)
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7Unpad: empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, fmt.Errorf("pkcs7Unpad: invalid padding value %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("pkcs7Unpad: invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

// aesEncrypt encrypts plaintext using AES-256-CBC with HMAC-SHA256.
// Returns: IV[16] + ciphertext + HMAC[32]  (Mythic's aes256_hmac format)
func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aesEncrypt: key must be 32 bytes, got %d", len(key))
	}

	// PKCS7 pad
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Build IV + ciphertext in a single buffer (IV occupies the first 16 bytes)
	ivAndCiphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ivAndCiphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("aesEncrypt: failed to generate IV: %w", err)
	}

	// AES-CBC encrypt into the buffer after the IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesEncrypt: failed to create cipher: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ivAndCiphertext[aes.BlockSize:], padded)

	// Compute HMAC-SHA256(key, IV + ciphertext)
	mac := hmac.New(sha256.New, key)
	mac.Write(ivAndCiphertext)
	hmacSum := mac.Sum(nil)

	// Return: IV[16] + ciphertext + HMAC[32]
	return append(ivAndCiphertext, hmacSum...), nil
}

// aesDecrypt decrypts data in the format: IV[16] + ciphertext + HMAC[32]
// using AES-256-CBC with HMAC-SHA256 verification (Mythic's aes256_hmac format).
func aesDecrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aesDecrypt: key must be 32 bytes, got %d", len(key))
	}
	if len(data) < aes.BlockSize+aes.BlockSize+32 {
		return nil, fmt.Errorf("aesDecrypt: data too short (%d bytes)", len(data))
	}

	// Split: IV[16] + ciphertext + HMAC[32]
	iv := data[:aes.BlockSize]
	hmacReceived := data[len(data)-32:]
	ciphertext := data[aes.BlockSize : len(data)-32]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("aesDecrypt: ciphertext length %d is not a multiple of block size", len(ciphertext))
	}

	// Verify HMAC-SHA256(key, IV + ciphertext)
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(ciphertext)
	hmacComputed := mac.Sum(nil)

	if !hmac.Equal(hmacReceived, hmacComputed) {
		return nil, errors.New("aesDecrypt: HMAC verification failed")
	}

	// AES-CBC decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesDecrypt: failed to create cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS7 unpad
	return pkcs7Unpad(plaintext)
}

// buildMythicFrame constructs a Mythic-formatted message: base64(uuidStr + body)
func buildMythicFrame(uuidStr string, body []byte) string {
	raw := make([]byte, 0, len(uuidStr)+len(body))
	raw = append(raw, []byte(uuidStr)...)
	raw = append(raw, body...)
	return base64.StdEncoding.EncodeToString(raw)
}

// parseMythicFrame base64-decodes a Mythic frame and splits the UUID prefix (36 chars) from the body.
func parseMythicFrame(base64Msg string) (string, []byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Msg)
	if err != nil {
		return "", nil, fmt.Errorf("parseMythicFrame: base64 decode failed: %w", err)
	}
	if len(decoded) < 36 {
		return "", nil, fmt.Errorf("parseMythicFrame: message too short (%d bytes)", len(decoded))
	}
	uuidStr := string(decoded[:36])
	body := decoded[36:]
	return uuidStr, body, nil
}
