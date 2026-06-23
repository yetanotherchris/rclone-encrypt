package encrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDeriveKey_DefaultSalt(t *testing.T) {
	k, err := DeriveKey("password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if k.DataKey == [32]byte{} {
		t.Error("DataKey should not be zero")
	}
	if k.NameKey == [32]byte{} {
		t.Error("NameKey should not be zero")
	}
	if k.NameTweak == [16]byte{} {
		t.Error("NameTweak should not be zero")
	}
}

func TestDeriveKey_CustomSalt(t *testing.T) {
	salt := []byte("custom-salt-1234")
	k1, err := DeriveKey("password", salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	k2, err := DeriveKey("password", salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if k1.DataKey != k2.DataKey {
		t.Error("same password + salt should produce same key")
	}

	k3, err := DeriveKey("password", nil)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if k1.DataKey == k3.DataKey {
		t.Error("different salt should produce different key")
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	k1, _ := DeriveKey("password1", nil)
	k2, _ := DeriveKey("password2", nil)
	if k1.DataKey == k2.DataKey {
		t.Error("different passwords should produce different keys")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		salt      []byte
		plaintext []byte
	}{
		{"empty", "test", nil, []byte{}},
		{"small", "test", nil, []byte("hello world")},
		{"exact-block", "test", nil, make([]byte, BlockDataSize)},
		{"one-byte-over", "test", nil, make([]byte, BlockDataSize+1)},
		{"multi-block", "test", nil, make([]byte, BlockDataSize*3+100)},
		{"custom-salt", "secret", []byte("0123456789abcdef"), []byte("data with custom salt")},
		{"binary", "p@ss", nil, []byte{0x00, 0xFF, 0xAB, 0xCD, 0x00, 0x01}},
		{"random-large", "test123", nil, randomBytes(200 * 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var encrypted bytes.Buffer
			_, err := Encrypt(&encrypted, bytes.NewReader(tt.plaintext), tt.password, tt.salt)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if encrypted.Len() < FileHeaderSize {
				t.Fatal("encrypted output too short")
			}
			header := encrypted.Bytes()[:FileHeaderSize]
			if string(header[:8]) != FileMagic {
				t.Error("bad magic bytes")
			}

			expectedEncSize := EncryptedSize(int64(len(tt.plaintext)))
			if int64(encrypted.Len()) != expectedEncSize {
				t.Errorf("encrypted size: got %d, want %d", encrypted.Len(), expectedEncSize)
			}

			var decrypted bytes.Buffer
			_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), tt.password, tt.salt)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted.Bytes(), tt.plaintext) {
				t.Fatalf("round-trip mismatch:\ngot:  %x\nwant: %x", decrypted.Bytes(), tt.plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_EmptyFile(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := Encrypt(&encrypted, bytes.NewReader(nil), "pwd", nil)
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}
	if encrypted.Len() != FileHeaderSize {
		t.Errorf("empty file encrypted size: got %d, want %d", encrypted.Len(), FileHeaderSize)
	}

	var decrypted bytes.Buffer
	_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), "pwd", nil)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}
	if decrypted.Len() != 0 {
		t.Errorf("decrypted empty should be empty, got %d bytes", decrypted.Len())
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	var encrypted bytes.Buffer
	plaintext := []byte("secret data")
	_, err := Encrypt(&encrypted, bytes.NewReader(plaintext), "correct-password", nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), "wrong-password", nil)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if err != ErrDecryptBlock {
		t.Errorf("expected ErrDecryptBlock, got: %v", err)
	}
}

func TestDecrypt_WrongSalt(t *testing.T) {
	salt1 := []byte("salt-for-encrypt")
	salt2 := []byte("salt-for-decrypt")
	var encrypted bytes.Buffer
	_, err := Encrypt(&encrypted, bytes.NewReader([]byte("data")), "password", salt1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), "password", salt2)
	if err == nil {
		t.Fatal("expected error for wrong salt, got nil")
	}
}

func TestDecrypt_BadMagic(t *testing.T) {
	r := bytes.NewReader(append(
		[]byte("NOTRCLONE\x00"),
		make([]byte, 23)...,
	))
	var buf bytes.Buffer
	_, err := Decrypt(&buf, r, "password", nil)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
	if err != ErrBadMagic {
		t.Errorf("expected ErrBadMagic, got: %v", err)
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	r := bytes.NewReader([]byte("RCLONE\x00\x00\x00\x00\x00"))
	var buf bytes.Buffer
	_, err := Decrypt(&buf, r, "password", nil)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestEncryptedSize(t *testing.T) {
	tests := []struct {
		plaintextSize int64
		want          int64
	}{
		{0, FileHeaderSize},
		{1, FileHeaderSize + BlockHeaderSize + 1},
		{BlockDataSize, FileHeaderSize + BlockSize},
		{BlockDataSize + 1, FileHeaderSize + BlockSize + BlockHeaderSize + 1},
		{BlockDataSize*3 + 100, FileHeaderSize + 3*BlockSize + BlockHeaderSize + 100},
	}
	for _, tt := range tests {
		got := EncryptedSize(tt.plaintextSize)
		if got != tt.want {
			t.Errorf("EncryptedSize(%d) = %d, want %d", tt.plaintextSize, got, tt.want)
		}
	}
}

func TestDecryptedSize(t *testing.T) {
	for _, pt := range []int64{0, 1, 100, BlockDataSize, BlockDataSize + 1, BlockDataSize * 3} {
		encSize := EncryptedSize(pt)
		decSize, err := DecryptedSize(encSize)
		if err != nil {
			t.Errorf("DecryptedSize(%d) unexpected error: %v", encSize, err)
			continue
		}
		if decSize != pt {
			t.Errorf("DecryptedSize(EncryptedSize(%d)) = %d, want %d", pt, decSize, pt)
		}
	}
}

func TestDecryptedSize_TooShort(t *testing.T) {
	_, err := DecryptedSize(0)
	if err == nil {
		t.Error("expected error for size 0")
	}
	result, err := DecryptedSize(FileHeaderSize)
	if err != nil {
		t.Errorf("header-only size should be valid (empty file): %v", err)
	}
	if result != 0 {
		t.Errorf("header-only size should decode to 0 bytes, got %d", result)
	}
	_, err = DecryptedSize(FileHeaderSize + BlockHeaderSize - 1)
	if err == nil {
		t.Error("expected error for size smaller than minimal block")
	}
}

func TestEncryptDecrypt_Streaming(t *testing.T) {
	plaintext := []byte("streaming test data - must survive encrypt/decrypt cycle")
	var encrypted bytes.Buffer

	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < len(plaintext); i += 5 {
			end := i + 5
			if end > len(plaintext) {
				end = len(plaintext)
			}
			pw.Write(plaintext[i:end])
		}
		pw.Close()
	}()

	_, err := Encrypt(&encrypted, pr, "stream-pwd", nil)
	if err != nil {
		t.Fatalf("Encrypt streaming failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), "stream-pwd", nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("streaming round-trip mismatch")
	}
}

func TestEncryptFile_DecryptFile(t *testing.T) {
	dir := t.TempDir()
	input := dir + "/input.bin"
	encrypted := dir + "/encrypted.bin"
	output := dir + "/output.bin"

	content := []byte("file-based encrypt/decrypt test")
	if err := os.WriteFile(input, content, 0644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := EncryptFile(input, encrypted, "file-pwd", nil); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	if err := DecryptFile(encrypted, output, "file-pwd", nil); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	result, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(result, content) {
		t.Fatalf("file round-trip mismatch: got %q, want %q", result, content)
	}
}

func TestEncryptDecrypt_DifferentPasswords(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := Encrypt(&encrypted, strings.NewReader("data"), "pwd1", nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var decrypted bytes.Buffer
	_, err = Decrypt(&decrypted, bytes.NewReader(encrypted.Bytes()), "pwd2", nil)
	if err == nil {
		t.Fatal("expected error decrypting with different password")
	}
}

func TestNewNonce_Unique(t *testing.T) {
	nonces := make(map[[FileNonceSize]byte]bool)
	for i := 0; i < 100; i++ {
		n := newNonce()
		if nonces[*n] {
			t.Fatal("nonce collision detected")
		}
		nonces[*n] = true
	}
}

func TestIncrementNonce(t *testing.T) {
	n := &[FileNonceSize]byte{}
	incrementNonce(n)
	if n[0] != 1 {
		t.Errorf("after increment, n[0] = %d, want 1", n[0])
	}

	n = &[FileNonceSize]byte{}
	n[0] = 0xFF
	incrementNonce(n)
	if n[0] != 0 || n[1] != 1 {
		t.Errorf("after carry: n[0]=%d, n[1]=%d, want 0, 1", n[0], n[1])
	}

	for i := range n {
		n[i] = 0xFF
	}
	incrementNonce(n)
	for i := 0; i < len(n)-1; i++ {
		if n[i] != 0 {
			t.Errorf("after all-FF: n[%d] = %d, want 0", i, n[i])
		}
	}
}

func TestDefaultSalt_Constant(t *testing.T) {
	expected := [16]byte{
		0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
		0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
	}
	if DefaultSalt != expected {
		t.Errorf("DefaultSalt mismatch:\ngot:  %v\nwant: %v", DefaultSalt, expected)
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
