package encrypt

import (
	"crypto/aes"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/rfjakob/eme"
)

type FilenameEncoding int

const (
	FilenameEncodingBase32 FilenameEncoding = iota
	FilenameEncodingBase64
)

func ParseFilenameEncoding(s string) (FilenameEncoding, error) {
	switch strings.ToLower(s) {
	case "base32":
		return FilenameEncodingBase32, nil
	case "base64":
		return FilenameEncodingBase64, nil
	default:
		return FilenameEncodingBase32, fmt.Errorf("unknown filename encoding: %q (supported: base32, base64)", s)
	}
}

const nameCipherBlockSize = 16

var (
	ErrPadding         = fmt.Errorf("invalid padding")
	ErrNotMultiple     = fmt.Errorf("encrypted name is not a multiple of block size")
	ErrBadBase32       = fmt.Errorf("encrypted filename contains padding characters")
	ErrBadBase64       = fmt.Errorf("decoding filename with base64")
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

func base64Encode(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

func base64Decode(s string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadBase64, err)
	}
	return decoded, nil
}

func EncryptFileName(nameKey, nameTweak []byte, plaintext string) (string, error) {
	return EncryptFileNameWithEncoding(nameKey, nameTweak, plaintext, FilenameEncodingBase32)
}

func EncryptFileNameWithEncoding(nameKey, nameTweak []byte, plaintext string, encoding FilenameEncoding) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(nameKey)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}

	padded := pkcs7p.Pad(nameCipherBlockSize, []byte(plaintext))
	ciphertext := eme.Transform(block, nameTweak, padded, eme.DirectionEncrypt)

	switch encoding {
	case FilenameEncodingBase64:
		return base64Encode(ciphertext), nil
	default:
		return base32Encode(ciphertext), nil
	}
}

func DecryptFileName(nameKey, nameTweak []byte, ciphertext string) (string, error) {
	return DecryptFileNameWithEncoding(nameKey, nameTweak, ciphertext, FilenameEncodingBase32)
}

func DecryptFileNameWithEncoding(nameKey, nameTweak []byte, ciphertext string, encoding FilenameEncoding) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	var decoded []byte
	var err error
	switch encoding {
	case FilenameEncodingBase64:
		decoded, err = base64Decode(ciphertext)
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
	default:
		decoded, err = base32Decode(ciphertext)
		if err != nil {
			return "", fmt.Errorf("base32 decode: %w", err)
		}
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
	return EncryptFilePathWithEncoding(key, path, FilenameEncodingBase32)
}

func EncryptFilePathWithEncoding(key *Key, path string, encoding FilenameEncoding) (string, error) {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		enc, err := EncryptFileNameWithEncoding(key.NameKey[:], key.NameTweak[:], seg, encoding)
		if err != nil {
			return "", fmt.Errorf("encrypt segment %q: %w", seg, err)
		}
		segments[i] = enc
	}
	return strings.Join(segments, "/"), nil
}

func DecryptFilePath(key *Key, path string) (string, error) {
	return DecryptFilePathWithEncoding(key, path, FilenameEncodingBase32)
}

func DecryptFilePathWithEncoding(key *Key, path string, encoding FilenameEncoding) (string, error) {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		dec, err := DecryptFileNameWithEncoding(key.NameKey[:], key.NameTweak[:], seg, encoding)
		if err != nil {
			return "", fmt.Errorf("decrypt segment %q: %w", seg, err)
		}
		segments[i] = dec
	}
	return strings.Join(segments, "/"), nil
}
