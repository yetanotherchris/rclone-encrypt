package encrypt

import (
	"strings"
	"testing"
)

func TestPKCS7_PadUnpad(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		n     int
	}{
		{"empty_16", []byte{}, 16},
		{"single_byte", []byte{0x01}, 16},
		{"exact_block", make([]byte, 16), 16},
		{"one_over", make([]byte, 17), 16},
		{"multi_block", make([]byte, 32), 16},
		{"multi_plus_one", make([]byte, 33), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7p.Pad(tt.n, tt.input)
			if len(padded)%tt.n != 0 {
				t.Fatalf("padded length %d is not multiple of %d", len(padded), tt.n)
			}
			unpadded, err := pkcs7p.Unpad(padded)
			if err != nil {
				t.Fatalf("Unpad failed: %v", err)
			}
			if !bytesEqual(unpadded, tt.input) {
				t.Fatalf("round-trip mismatch: got %x, want %x", unpadded, tt.input)
			}
		})
	}
}

func bytesEqual(a, b []byte) bool {
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

func TestPKCS7_Unpad_Invalid(t *testing.T) {
	_, err := pkcs7p.Unpad([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	_, err = pkcs7p.Unpad([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for zero padding")
	}
	_, err = pkcs7p.Unpad([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for mismatched padding")
	}
}

func TestBase32_RoundTrip(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello",
		"hello world",
		strings.Repeat("x", 100),
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if tt == "" {
				return
			}
			encoded := base32Encode([]byte(tt))
			if encoded != strings.ToLower(encoded) {
				t.Error("encoded string should be lowercase")
			}
			if strings.Contains(encoded, "=") {
				t.Error("encoded string should not contain padding")
			}
			decoded, err := base32Decode(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if string(decoded) != tt {
				t.Fatalf("round-trip mismatch: got %q, want %q", string(decoded), tt)
			}
		})
	}
}

func TestBase32Decode_RejectsPadding(t *testing.T) {
	_, err := base32Decode("test====")
	if err == nil {
		t.Fatal("expected error for padded input")
	}
}

func TestFilenameEncryptDecrypt_RoundTrip(t *testing.T) {
	key, err := DeriveKey("test-password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	names := []string{
		"a",
		"hello.txt",
		"document.pdf",
		"my file with spaces.txt",
		"UPPERCASE.TXT",
		strings.Repeat("x", 50),
		strings.Repeat("x", 200),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			enc, err := EncryptFileName(key.NameKey[:], key.NameTweak[:], name)
			if err != nil {
				t.Fatalf("EncryptFileName failed: %v", err)
			}
			if enc == "" {
				t.Fatal("encrypted name should not be empty")
			}
			if strings.Contains(enc, "=") {
				t.Error("encrypted name should not contain padding")
			}

			dec, err := DecryptFileName(key.NameKey[:], key.NameTweak[:], enc)
			if err != nil {
				t.Fatalf("DecryptFileName failed: %v", err)
			}
			if dec != name {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, name)
			}
		})
	}
}

func TestFilePathEncryptDecrypt_RoundTrip(t *testing.T) {
	key, err := DeriveKey("test-password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	paths := []string{
		"file.txt",
		"dir/file.txt",
		"a/b/c/d/file.txt",
		"top/middle/bottom",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			enc, err := EncryptFilePath(key, path)
			if err != nil {
				t.Fatalf("EncryptFilePath failed: %v", err)
			}
			if enc == path {
				t.Error("encrypted path should differ from plaintext")
			}

			dec, err := DecryptFilePath(key, enc)
			if err != nil {
				t.Fatalf("DecryptFilePath failed: %v", err)
			}
			if dec != path {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, path)
			}
		})
	}
}

func TestFilenameDeterministic(t *testing.T) {
	key, err := DeriveKey("test-password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	name := "hello.txt"
	enc1, _ := EncryptFileName(key.NameKey[:], key.NameTweak[:], name)
	enc2, _ := EncryptFileName(key.NameKey[:], key.NameTweak[:], name)
	if enc1 != enc2 {
		t.Fatal("filename encryption should be deterministic")
	}
}

func TestFilenameDifferentKey(t *testing.T) {
	key1, _ := DeriveKey("password1", nil)
	key2, _ := DeriveKey("password2", nil)

	name := "test.txt"
	enc1, _ := EncryptFileName(key1.NameKey[:], key1.NameTweak[:], name)
	enc2, _ := EncryptFileName(key2.NameKey[:], key2.NameTweak[:], name)
	if enc1 == enc2 {
		t.Fatal("different passwords should produce different encrypted names")
	}
}

func TestFilenameEncryptDecrypt_WrongPassword(t *testing.T) {
	key1, _ := DeriveKey("correct", nil)
	key2, _ := DeriveKey("wrong", nil)

	name := "secret.doc"
	enc, _ := EncryptFileName(key1.NameKey[:], key1.NameTweak[:], name)
	_, err := DecryptFileName(key2.NameKey[:], key2.NameTweak[:], enc)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestFilenameEmpty(t *testing.T) {
	key, _ := DeriveKey("pwd", nil)
	enc, err := EncryptFileName(key.NameKey[:], key.NameTweak[:], "")
	if err != nil {
		t.Fatalf("EncryptFileName empty should not error: %v", err)
	}
	if enc != "" {
		t.Fatalf("empty string should encrypt to empty, got %q", enc)
	}

	dec, err := DecryptFileName(key.NameKey[:], key.NameTweak[:], "")
	if err != nil {
		t.Fatalf("DecryptFileName empty should not error: %v", err)
	}
	if dec != "" {
		t.Fatalf("empty string should decrypt to empty, got %q", dec)
	}
}

func TestBase64_RoundTrip(t *testing.T) {
	tests := []string{
		"a",
		"hello",
		"hello world",
		strings.Repeat("x", 100),
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			encoded := base64Encode([]byte(tt))
			if strings.ContainsAny(encoded, "+/=") {
				t.Error("base64 URL-safe should not contain + / or =")
			}
			decoded, err := base64Decode(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if string(decoded) != tt {
				t.Fatalf("round-trip mismatch: got %q, want %q", string(decoded), tt)
			}
		})
	}
}

func TestParseFilenameEncoding(t *testing.T) {
	tests := []struct {
		input string
		want  FilenameEncoding
	}{
		{"base32", FilenameEncodingBase32},
		{"BASE32", FilenameEncodingBase32},
		{"Base32", FilenameEncodingBase32},
		{"base64", FilenameEncodingBase64},
		{"BASE64", FilenameEncodingBase64},
		{"Base64", FilenameEncodingBase64},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFilenameEncoding(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseFilenameEncoding_Invalid(t *testing.T) {
	_, err := ParseFilenameEncoding("base16")
	if err == nil {
		t.Fatal("expected error for invalid encoding")
	}
}

func TestFilenameEncryptDecrypt_Base64Encoding(t *testing.T) {
	key, err := DeriveKey("test-password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	name := "hello.txt"
	enc, err := EncryptFileName(key.NameKey[:], key.NameTweak[:], name)
	if err != nil {
		t.Fatalf("EncryptFileName failed: %v", err)
	}

	dec, err := DecryptFileNameWithEncoding(key.NameKey[:], key.NameTweak[:], enc, FilenameEncodingBase64)
	if err == nil {
		t.Fatal("expected error decrypting base32-encoded name with base64")
	}
	_ = dec

	dec, err = DecryptFileNameWithEncoding(key.NameKey[:], key.NameTweak[:], enc, FilenameEncodingBase32)
	if err != nil {
		t.Fatalf("DecryptFileNameWithEncoding base32 failed: %v", err)
	}
	if dec != name {
		t.Fatalf("got %q, want %q", dec, name)
	}
}

func TestFilePathDecrypt_Base64Encoding(t *testing.T) {
	key, err := DeriveKey("test-password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	enc, err := EncryptFilePath(key, "dir/file.txt")
	if err != nil {
		t.Fatalf("EncryptFilePath failed: %v", err)
	}

	dec, err := DecryptFilePathWithEncoding(key, enc, FilenameEncodingBase64)
	if err == nil {
		t.Fatal("expected error decrypting base32-encoded path with base64")
	}
	_ = dec

	dec, err = DecryptFilePathWithEncoding(key, enc, FilenameEncodingBase32)
	if err != nil {
		t.Fatalf("DecryptFilePathWithEncoding base32 failed: %v", err)
	}
	if dec != "dir/file.txt" {
		t.Fatalf("got %q, want %q", dec, "dir/file.txt")
	}
}

func TestFileNameEncoding_Base32Properties(t *testing.T) {
	key, _ := DeriveKey("pwd", nil)
	enc, _ := EncryptFileName(key.NameKey[:], key.NameTweak[:], "test.txt")
	if enc == "" {
		t.Fatal("should not be empty")
	}
	for _, c := range enc {
		if c >= 'A' && c <= 'Z' {
			t.Fatal("should not contain uppercase letters (for case-insensitive FS compatibility)")
		}
	}
}
