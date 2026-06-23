package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "rclone-encrypt")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestCLI_EncryptDecrypt_PasswordFlag(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")

	if err := os.WriteFile(input, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	out, errOut, err := runCLI(t, bin, "encrypt", "--password", "test123", input, enc)
	if err != nil {
		t.Fatalf("encrypt failed: %v\nstderr: %s", err, errOut)
	}
	if !strings.Contains(errOut, "Encrypting") {
		t.Errorf("expected progress message, got: %s", errOut)
	}
	if !strings.Contains(errOut, "WARNING") {
		t.Error("expected WARNING about --password")
	}
	_ = out

	out, errOut, err = runCLI(t, bin, "decrypt", "--password", "test123", enc, output)
	if err != nil {
		t.Fatalf("decrypt failed: %v\nstderr: %s", err, errOut)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "hello world" {
		t.Errorf("decrypted content: got %q, want %q", string(result), "hello world")
	}
}

func TestCLI_EncryptDecrypt_WithSalt(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"

	if err := os.WriteFile(input, []byte("salted data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "pwd", "--salt", salt, input, enc)
	if err != nil {
		t.Fatalf("encrypt with salt failed: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", "--password", "pwd", "--salt", salt, enc, output)
	if err != nil {
		t.Fatalf("decrypt with salt failed: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "salted data" {
		t.Errorf("decrypted content: got %q, want %q", string(result), "salted data")
	}
}

func TestCLI_EncryptDecrypt_DefaultSalt(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")

	if err := os.WriteFile(input, []byte("default salt test"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "default-salt-pwd", input, enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", "--password", "default-salt-pwd", enc, output)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "default salt test" {
		t.Errorf("got %q, want %q", string(result), "default salt test")
	}
}

func TestCLI_EnvVarPassword(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")

	if err := os.WriteFile(input, []byte("env var test"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RCLONE_ENCRYPT_PASSWORD", "env-password")

	_, _, err := runCLI(t, bin, "encrypt", input, enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", enc, output)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "env var test" {
		t.Errorf("got %q, want %q", string(result), "env var test")
	}
}

func TestCLI_EnvVarSalt(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")
	salt := "aabbccddaabbccddaabbccddaabbccdd"

	if err := os.WriteFile(input, []byte("env salt test"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RCLONE_ENCRYPT_PASSWORD", "pwd")
	t.Setenv("RCLONE_ENCRYPT_SALT", salt)

	_, _, err := runCLI(t, bin, "encrypt", input, enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", enc, output)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "env salt test" {
		t.Errorf("got %q, want %q", string(result), "env salt test")
	}
}

func TestCLI_WrongPassword(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")

	if err := os.WriteFile(input, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "correct", input, enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, stderr, err := runCLI(t, bin, "decrypt", "--password", "wrong", enc, filepath.Join(dir, "out.txt"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(stderr, "wrong password") {
		t.Errorf("expected 'wrong password' in stderr, got: %s", stderr)
	}
}

func TestCLI_WrongSalt(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")

	if err := os.WriteFile(input, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "pwd", "--salt", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", input, enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, stderr, err := runCLI(t, bin, "decrypt", "--password", "pwd", "--salt", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", enc, filepath.Join(dir, "out.txt"))
	if err == nil {
		t.Fatal("expected error for wrong salt")
	}
	if !strings.Contains(stderr, "wrong password") {
		t.Errorf("expected 'wrong password' in stderr, got: %s", stderr)
	}
}

func TestCLI_BadMagicFile(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.bin")

	badHeader := append([]byte("BADMAGIC"), make([]byte, 24)...)
	if err := os.WriteFile(badFile, badHeader, 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := runCLI(t, bin, "decrypt", "--password", "pwd", badFile, filepath.Join(dir, "out.txt"))
	if err == nil {
		t.Fatal("expected error for bad file")
	}
	if !strings.Contains(stderr, "bad magic") {
		t.Errorf("expected 'bad magic' in stderr, got: %s", stderr)
	}
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	stdout, stderr, err := runCLI(t, bin, "version")
	if err != nil {
		t.Fatalf("version failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "rclone-encrypt") {
		t.Errorf("expected 'rclone-encrypt' in version output, got: %s", stdout)
	}
}

func TestCLI_GenerateSalt(t *testing.T) {
	bin := buildBinary(t)
	stdout, stderr, err := runCLI(t, bin, "generate-salt")
	if err != nil {
		t.Fatalf("generate-salt failed: %v\nstderr: %s", err, stderr)
	}
	salt := strings.TrimSpace(stdout)
	if len(salt) != 32 {
		t.Errorf("expected 32 hex chars, got %d: %q", len(salt), salt)
	}
	for _, c := range salt {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character in salt: %c", c)
		}
	}
}

func TestCLI_EncryptDecrypt_Flags(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")

	if err := os.WriteFile(input, []byte("flag test"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "pwd", "--input", input, "--output", enc)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", "--password", "pwd", "--input", enc, "--output", output)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "flag test" {
		t.Errorf("got %q, want %q", string(result), "flag test")
	}
}

func TestCLI_ShortCommands(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	enc := filepath.Join(dir, "encrypted.bin")
	output := filepath.Join(dir, "output.txt")

	if err := os.WriteFile(input, []byte("short cmd"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "e", "--password", "pwd", input, enc)
	if err != nil {
		t.Fatalf("short encrypt: %v", err)
	}

	_, _, err = runCLI(t, bin, "d", "--password", "pwd", enc, output)
	if err != nil {
		t.Fatalf("short decrypt: %v", err)
	}

	result, _ := os.ReadFile(output)
	if string(result) != "short cmd" {
		t.Errorf("got %q, want %q", string(result), "short cmd")
	}
}

func TestCLI_MissingArgs(t *testing.T) {
	bin := buildBinary(t)

	_, stderr, err := runCLI(t, bin, "encrypt")
	if err == nil {
		t.Fatal("expected error for missing args")
	}
	if !strings.Contains(stderr, "input file is required") {
		t.Errorf("expected 'input file is required', got: %s", stderr)
	}
}

func TestCLI_InvalidSalt(t *testing.T) {
	bin := buildBinary(t)
	_, stderr, err := runCLI(t, bin, "encrypt", "--password", "pwd", "--salt", "not-hex", "input.txt", "out.bin")
	if err == nil {
		t.Fatal("expected error for invalid salt")
	}
	if !strings.Contains(stderr, "invalid salt") {
		t.Errorf("expected 'invalid salt' in stderr, got: %s", stderr)
	}
}

func TestCLI_EncryptDecrypt_LargeFile(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "large_input.bin")
	enc := filepath.Join(dir, "large_encrypted.bin")
	output := filepath.Join(dir, "large_output.bin")

	data := make([]byte, 200*1024)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(input, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, bin, "encrypt", "--password", "large-file-pwd", input, enc)
	if err != nil {
		t.Fatalf("encrypt large: %v", err)
	}

	_, _, err = runCLI(t, bin, "decrypt", "--password", "large-file-pwd", enc, output)
	if err != nil {
		t.Fatalf("decrypt large: %v", err)
	}

	result, _ := os.ReadFile(output)
	if !bytes.Equal(result, data) {
		t.Fatal("large file round-trip mismatch")
	}
}

func TestCLI_EncryptDecrypt_AutoDeriveOutput(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "myfile.txt")
	if err := os.WriteFile(input, []byte("auto-derive test"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RCLONE_ENCRYPT_PASSWORD", "test-pwd")

	stdout, stderr, err := runCLI(t, bin, "encrypt", input)
	if err != nil {
		t.Fatalf("encrypt with auto-derive failed: %v\nstderr: %s", err, stderr)
	}
	_ = stdout
	if !strings.Contains(stderr, "Derived output filename") {
		t.Errorf("expected derivation message, got: %s", stderr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var encFile string
	for _, e := range entries {
		if e.Name() != "myfile.txt" {
			encFile = filepath.Join(dir, e.Name())
			break
		}
	}
	if encFile == "" {
		t.Fatal("no encrypted file found in output dir")
	}

	stdout, stderr, err = runCLI(t, bin, "decrypt", encFile)
	if err != nil {
		t.Fatalf("decrypt with auto-derive failed: %v\nstderr: %s", err, stderr)
	}
	_ = stdout
	if !strings.Contains(stderr, "Derived output filename") {
		t.Errorf("expected derivation message, got: %s", stderr)
	}

	result, _ := os.ReadFile(filepath.Join(dir, "myfile.txt"))
	if string(result) != "auto-derive test" {
		t.Errorf("got %q, want %q", string(result), "auto-derive test")
	}
}

func TestCLI_EncryptDecrypt_OutputFlagOverridesAutoDerive(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "override_test.txt")
	output := filepath.Join(dir, "explicit_output.bin")
	if err := os.WriteFile(input, []byte("override test"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("RCLONE_ENCRYPT_PASSWORD", "pwd")

	stdout, stderr, err := runCLI(t, bin, "encrypt", "--output", output, input)
	if err != nil {
		t.Fatalf("encrypt failed: %v\nstderr: %s", err, stderr)
	}
	_ = stdout

	if strings.Contains(stderr, "Derived output filename") {
		t.Error("should NOT derive output when --output is provided")
	}

	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Fatalf("output file %s was not created", output)
	}

	stdout, stderr, err = runCLI(t, bin, "decrypt", "--output", filepath.Join(dir, "restored.txt"), output)
	if err != nil {
		t.Fatalf("decrypt failed: %v\nstderr: %s", err, stderr)
	}
	_ = stdout

	if strings.Contains(stderr, "Derived output filename") {
		t.Error("should NOT derive output when --output is provided on decrypt")
	}

	result, _ := os.ReadFile(filepath.Join(dir, "restored.txt"))
	if string(result) != "override test" {
		t.Errorf("got %q, want %q", string(result), "override test")
	}
}
