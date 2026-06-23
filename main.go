package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/yetanotherchris/rclone-encrypt/internal/encrypt"
)

var version = "1.0.1"

func main() {
	if err := run(); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

type passwordFlag string

func (f *passwordFlag) String() string { return "********" }
func (f *passwordFlag) Set(s string) error {
	*f = passwordFlag(s)
	return nil
}
func (f *passwordFlag) IsBoolFlag() bool { return false }

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	cmd := os.Args[1]
	switch cmd {
	case "encrypt", "e":
		return runEncrypt(os.Args[2:])
	case "decrypt", "d":
		return runDecrypt(os.Args[2:])
	case "generate-salt":
		return runGenerateSalt()
	case "version", "--version", "-v":
		fmt.Println("rclone-encrypt", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s\n\n", cmd)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: rclone-encrypt <command> [options]

Encrypts and decrypts files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt).

Commands:
  encrypt       Encrypt a file
  decrypt       Decrypt a file
  generate-salt Generate a random 16-byte salt (hex-encoded)
  version       Print version

Use 'rclone-encrypt <command> --help' for command-specific options.
`)
}

func printEncryptUsage() {
	fmt.Fprint(os.Stderr, `Usage: rclone-encrypt encrypt [options] <input> [<output>]

Encrypt a file using rclone-compatible encryption.
If output is omitted, the filename is encrypted with AES-EME and used as the output name.

Options:
  --password             Password (WARNING: insecure - use env var RCLONE_ENCRYPT_PASSWORD instead, or omit to be prompted)
  --salt                 Optional hex-encoded salt (omit to use rclone's default salt; also via RCLONE_ENCRYPT_SALT env var)
  --filename-encoding    Filename encoding for encrypted filenames: base32 (default) or base64 (also via RCLONE_ENCRYPT_FILENAME_ENCODING env var)
  -i, --input            Input file path
  -o, --output           Output file path (default: auto-derived from input filename)

Positional arguments: <input> [<output>]
`)
}

func printDecryptUsage() {
	fmt.Fprint(os.Stderr, `Usage: rclone-encrypt decrypt [options] <input> [<output>]

Decrypt a file encrypted with rclone-compatible encryption.
If output is omitted, the encrypted filename is decrypted with AES-EME and used as the output name.

Options:
  --password             Password (WARNING: insecure - use env var RCLONE_ENCRYPT_PASSWORD instead, or omit to be prompted)
  --salt                 Optional hex-encoded salt (omit to use rclone's default salt; also via RCLONE_ENCRYPT_SALT env var)
  --filename-encoding    Filename encoding for decryption: base32 (default) or base64 (also via RCLONE_ENCRYPT_FILENAME_ENCODING env var)
  -i, --input            Input file path
  -o, --output           Output file path (default: auto-derived from encrypted filename)

Positional arguments: <input> [<output>]
`)
}

func deriveEncryptOutput(input string, password string, salt []byte, filenameEncoding encrypt.FilenameEncoding) (string, error) {
	key, err := encrypt.DeriveKey(password, salt)
	if err != nil {
		return "", fmt.Errorf("derive key for filename: %w", err)
	}
	encPath, err := encrypt.EncryptFilePathWithEncoding(key, input, filenameEncoding)
	if err != nil {
		return "", fmt.Errorf("encrypt filename: %w", err)
	}
	return encPath, nil
}

func deriveDecryptOutput(encryptedInput string, password string, salt []byte, filenameEncoding encrypt.FilenameEncoding) (string, error) {
	key, err := encrypt.DeriveKey(password, salt)
	if err != nil {
		return "", fmt.Errorf("derive key for filename: %w", err)
	}
	decPath, err := encrypt.DecryptFilePathWithEncoding(key, encryptedInput, filenameEncoding)
	if err != nil {
		return "", fmt.Errorf("decrypt filename: %w", err)
	}
	return decPath, nil
}

func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.Usage = printEncryptUsage

	var pw passwordFlag
	var saltHex string
	var input, output string
	var filenameEncodingStr string
	fs.Var(&pw, "password", "Password (WARNING: insecure on command line)")
	fs.StringVar(&saltHex, "salt", "", "Optional hex-encoded salt")
	fs.StringVar(&filenameEncodingStr, "filename-encoding", "", "Filename encoding: base32 (default) or base64")
	fs.StringVar(&input, "input", "", "Input file path")
	fs.StringVar(&input, "i", "", "Input file path (shorthand)")
	fs.StringVar(&output, "output", "", "Output file path (shorthand)")
	fs.StringVar(&output, "o", "", "Output file path (shorthand)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	password := string(pw)
	remaining := fs.Args()

	if input == "" && len(remaining) > 0 {
		input = remaining[0]
		remaining = remaining[1:]
	}
	if output == "" && len(remaining) > 0 {
		output = remaining[0]
		remaining = remaining[1:]
	}
	_ = remaining

	if input == "" {
		printEncryptUsage()
		return fmt.Errorf("input file is required")
	}

	password, err := resolvePassword(password)
	if err != nil {
		return err
	}

	salt, err := resolveSalt(saltHex)
	if err != nil {
		return err
	}

	filenameEncoding, err := resolveFilenameEncoding(filenameEncodingStr)
	if err != nil {
		return err
	}

	if output == "" {
		fileSegment := input
		dirPrefix := ""
		if idx := strings.LastIndex(input, "/"); idx >= 0 {
			dirPrefix = input[:idx+1]
			fileSegment = input[idx+1:]
		}
		if idx := strings.LastIndex(input, "\\"); idx >= 0 {
			dirPrefix = input[:idx+1]
			fileSegment = input[idx+1:]
		}
		derived, err := deriveEncryptOutput(fileSegment, password, salt, filenameEncoding)
		if err != nil {
			return fmt.Errorf("derive output filename: %w", err)
		}
		output = dirPrefix + derived
		fmt.Fprintf(os.Stderr, "Derived output filename: %s\n", output)
	}

	fmt.Fprintf(os.Stderr, "Encrypting %s -> %s ...\n", input, output)
	if err := encrypt.EncryptFile(input, output, password, salt); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Done.")
	return nil
}

func runDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.Usage = printDecryptUsage

	var pw passwordFlag
	var saltHex string
	var input, output string
	var filenameEncodingStr string
	fs.Var(&pw, "password", "Password (WARNING: insecure on command line)")
	fs.StringVar(&saltHex, "salt", "", "Optional hex-encoded salt")
	fs.StringVar(&filenameEncodingStr, "filename-encoding", "", "Filename encoding: base32 (default) or base64")
	fs.StringVar(&input, "input", "", "Input file path")
	fs.StringVar(&input, "i", "", "Input file path (shorthand)")
	fs.StringVar(&output, "output", "", "Output file path")
	fs.StringVar(&output, "o", "", "Output file path (shorthand)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	password := string(pw)
	remaining := fs.Args()

	if input == "" && len(remaining) > 0 {
		input = remaining[0]
		remaining = remaining[1:]
	}
	if output == "" && len(remaining) > 0 {
		output = remaining[0]
		remaining = remaining[1:]
	}
	_ = remaining

	if input == "" {
		printDecryptUsage()
		return fmt.Errorf("input file is required")
	}

	password, err := resolvePassword(password)
	if err != nil {
		return err
	}

	salt, err := resolveSalt(saltHex)
	if err != nil {
		return err
	}

	filenameEncoding, err := resolveFilenameEncoding(filenameEncodingStr)
	if err != nil {
		return err
	}

	if output == "" {
		fileSegment := input
		dirPrefix := ""
		if idx := strings.LastIndex(input, "/"); idx >= 0 {
			dirPrefix = input[:idx+1]
			fileSegment = input[idx+1:]
		}
		if idx := strings.LastIndex(input, "\\"); idx >= 0 {
			dirPrefix = input[:idx+1]
			fileSegment = input[idx+1:]
		}
		derived, err := deriveDecryptOutput(fileSegment, password, salt, filenameEncoding)
		if err != nil {
			return fmt.Errorf("derive output filename: %w", err)
		}
		output = dirPrefix + derived
		fmt.Fprintf(os.Stderr, "Derived output filename: %s\n", output)
	}

	fmt.Fprintf(os.Stderr, "Decrypting %s -> %s ...\n", input, output)
	if err := encrypt.DecryptFile(input, output, password, salt); err != nil {
		if errors.Is(err, encrypt.ErrBadMagic) {
			return fmt.Errorf("not an rclone-encrypted file (bad magic)")
		}
		if errors.Is(err, encrypt.ErrDecryptBlock) {
			return fmt.Errorf("wrong password or corrupt data")
		}
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Done.")
	return nil
}

func runGenerateSalt() error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	fmt.Println(hex.EncodeToString(salt))
	return nil
}

func resolvePassword(fromFlag string) (string, error) {
	if fromFlag != "" {
		fmt.Fprintln(os.Stderr, "WARNING: Using --password on the command line is insecure.")
		fmt.Fprintln(os.Stderr, "         The password is visible in process listings and shell history.")
		fmt.Fprintln(os.Stderr, "         Use RCLONE_ENCRYPT_PASSWORD environment variable instead,")
		fmt.Fprintln(os.Stderr, "         or omit --password to be prompted securely.")
		fmt.Fprintln(os.Stderr, "         If you must use --password, wipe your terminal history afterwards.")
		return fromFlag, nil
	}

	if pw := os.Getenv("RCLONE_ENCRYPT_PASSWORD"); pw != "" {
		return pw, nil
	}

	fmt.Fprint(os.Stderr, "Password: ")
	bytePW, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := string(bytePW)
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return pw, nil
}

func resolveFilenameEncoding(fromFlag string) (encrypt.FilenameEncoding, error) {
	if fromFlag == "" {
		if envEnc := os.Getenv("RCLONE_ENCRYPT_FILENAME_ENCODING"); envEnc != "" {
			fromFlag = envEnc
		}
	}
	if fromFlag == "" {
		return encrypt.FilenameEncodingBase32, nil
	}
	return encrypt.ParseFilenameEncoding(fromFlag)
}

func resolveSalt(hexSalt string) ([]byte, error) {
	if hexSalt == "" {
		if envSalt := os.Getenv("RCLONE_ENCRYPT_SALT"); envSalt != "" {
			hexSalt = envSalt
		}
	}

	if hexSalt == "" {
		return nil, nil
	}

	salt, err := hex.DecodeString(strings.TrimSpace(hexSalt))
	if err != nil {
		return nil, fmt.Errorf("invalid salt hex: %w", err)
	}
	return salt, nil
}


