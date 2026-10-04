package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	fileMagic      = "RCLONE\x00\x00"
	fileHeaderSize = 32
	blockDataSize  = 64 * 1024
	blockOverhead  = secretbox.Overhead
)

var defaultSalt = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}

type FilenameEncoding string

const (
	Base32 FilenameEncoding = "base32"
	Base64 FilenameEncoding = "base64"
)

type Cipher struct {
	dataKey  [32]byte
	nameKey  [32]byte
	tweak    [16]byte
	block    cipher.Block
	encoding FilenameEncoding
}

func New(password, salt string, encoding FilenameEncoding) (*Cipher, error) {
	if encoding == "" {
		encoding = Base32
	}
	if encoding != Base32 && encoding != Base64 {
		return nil, fmt.Errorf("unsupported filename encoding %q (use base32 or base64)", encoding)
	}
	var key []byte
	var err error
	if password == "" {
		key = make([]byte, 80)
	} else {
		saltBytes := defaultSalt
		if salt != "" {
			saltBytes = []byte(salt)
		}
		key, err = scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, 80)
		if err != nil {
			return nil, fmt.Errorf("derive key: %w", err)
		}
	}
	block, err := aes.NewCipher(key[32:64])
	if err != nil {
		return nil, err
	}
	c := &Cipher{encoding: encoding, block: block}
	copy(c.dataKey[:], key[:32])
	copy(c.nameKey[:], key[32:64])
	copy(c.tweak[:], key[64:])
	return c, nil
}

func (c *Cipher) encode(data []byte) string {
	if c.encoding == Base64 {
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return strings.ToLower(strings.TrimRight(base32.HexEncoding.EncodeToString(data), "="))
}

func (c *Cipher) decode(s string) ([]byte, error) {
	if c.encoding == Base64 {
		return base64.RawURLEncoding.DecodeString(s)
	}
	if strings.Contains(s, "=") {
		return nil, errors.New("base32 filename must not contain padding")
	}
	padded := strings.ToUpper(s) + strings.Repeat("=", (8-len(s)%8)%8)
	return base32.HexEncoding.DecodeString(padded)
}

func (c *Cipher) EncryptFilename(name string) string {
	if name == "" {
		return ""
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		padded := pkcs7Pad([]byte(part), aes.BlockSize)
		parts[i] = c.encode(eme.Transform(c.block, c.tweak[:], padded, eme.DirectionEncrypt))
	}
	return strings.Join(parts, "/")
}

func (c *Cipher) DecryptFilename(name string) (string, error) {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		encoded, err := c.decode(part)
		if err != nil {
			return "", err
		}
		if len(encoded) == 0 || len(encoded)%aes.BlockSize != 0 {
			return "", errors.New("invalid encrypted filename block size")
		}
		plain, err := pkcs7Unpad(eme.Transform(c.block, c.tweak[:], encoded, eme.DirectionDecrypt))
		if err != nil {
			return "", err
		}
		parts[i] = string(plain)
	}
	return strings.Join(parts, "/"), nil
}

func (c *Cipher) EncryptData(plain []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	out := append([]byte(fileMagic), nonce[:]...)
	for len(plain) > 0 {
		n := len(plain)
		if n > blockDataSize {
			n = blockDataSize
		}
		out = secretbox.Seal(out, plain[:n], &nonce, &c.dataKey)
		plain = plain[n:]
		incrementNonce(&nonce)
	}
	return out, nil
}

func (c *Cipher) DecryptData(encrypted []byte) ([]byte, error) {
	if len(encrypted) < fileHeaderSize || string(encrypted[:len(fileMagic)]) != fileMagic {
		return nil, errors.New("not an rclone encrypted file")
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[len(fileMagic):fileHeaderSize])
	var out []byte
	encrypted = encrypted[fileHeaderSize:]
	for len(encrypted) > 0 {
		if len(encrypted) <= blockOverhead {
			return nil, errors.New("truncated encrypted block")
		}
		plain, ok := secretbox.Open(nil, encrypted, &nonce, &c.dataKey)
		if !ok {
			return nil, errors.New("authentication failed (wrong password or corrupted file)")
		}
		out = append(out, plain...)
		encrypted = encrypted[len(plain)+blockOverhead:]
		incrementNonce(&nonce)
	}
	return out, nil
}

func incrementNonce(n *[24]byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func pkcs7Pad(data []byte, size int) []byte {
	padding := size - len(data)%size
	return append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty padded filename")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize || n > len(data) {
		return nil, errors.New("invalid padded filename")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("invalid padded filename")
		}
	}
	return data[:len(data)-n], nil
}
