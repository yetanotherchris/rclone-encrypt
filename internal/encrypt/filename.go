package encrypt

import (
	"crypto/aes"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/rfjakob/eme"
)

const nameCipherBlockSize = 16

var (
	ErrPadding         = fmt.Errorf("invalid padding")
	ErrNotMultiple     = fmt.Errorf("encrypted name is not a multiple of block size")
	ErrBadBase32       = fmt.Errorf("encrypted filename contains padding characters")
)

type pkcs7 struct{}

func (pkcs7) Pad(n int, src []byte) []byte {
	padding := n - len(src)%n
	out := make([]byte, len(src)+padding)
	copy(out, src)
	for i := len(src); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func (pkcs7) Unpad(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, ErrPadding
	}
	padding := int(src[len(src)-1])
	if padding == 0 || padding > len(src) {
		return nil, ErrPadding
	}
	for _, b := range src[len(src)-padding:] {
		if int(b) != padding {
			return nil, ErrPadding
		}
	}
	return src[:len(src)-padding], nil
}

var pkcs7p = pkcs7{}

func base32Encode(src []byte) string {
	encoded := base32.HexEncoding.EncodeToString(src)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded)
}

func base32Decode(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, ErrBadBase32
	}
	roundUp := (len(s) + 7) &^ 7
	equals := roundUp - len(s)
	s = strings.ToUpper(s) + "========"[:equals]
	return base32.HexEncoding.DecodeString(s)
}

func EncryptFileName(nameKey, nameTweak []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(nameKey)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}

	padded := pkcs7p.Pad(nameCipherBlockSize, []byte(plaintext))
	ciphertext := eme.Transform(block, nameTweak, padded, eme.DirectionEncrypt)
	return base32Encode(ciphertext), nil
}

func DecryptFileName(nameKey, nameTweak []byte, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	decoded, err := base32Decode(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base32 decode: %w", err)
	}

	if len(decoded) == 0 || len(decoded)%nameCipherBlockSize != 0 {
		return "", ErrNotMultiple
	}

	block, err := aes.NewCipher(nameKey)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}

	plainBytes := eme.Transform(block, nameTweak, decoded, eme.DirectionDecrypt)
	unpadded, err := pkcs7p.Unpad(plainBytes)
	if err != nil {
		return "", fmt.Errorf("pkcs7 unpad: %w", err)
	}

	return string(unpadded), nil
}

func EncryptFilePath(key *Key, path string) (string, error) {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		enc, err := EncryptFileName(key.NameKey[:], key.NameTweak[:], seg)
		if err != nil {
			return "", fmt.Errorf("encrypt segment %q: %w", seg, err)
		}
		segments[i] = enc
	}
	return strings.Join(segments, "/"), nil
}

func DecryptFilePath(key *Key, path string) (string, error) {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		dec, err := DecryptFileName(key.NameKey[:], key.NameTweak[:], seg)
		if err != nil {
			return "", fmt.Errorf("decrypt segment %q: %w", seg, err)
		}
		segments[i] = dec
	}
	return strings.Join(segments, "/"), nil
}
