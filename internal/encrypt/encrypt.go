package encrypt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	FileMagic     = "RCLONE\x00\x00"
	FileMagicSize = 8
	FileNonceSize = 24
	FileHeaderSize = 32

	BlockHeaderSize = secretbox.Overhead // 16
	BlockDataSize   = 64 * 1024          // 65536
	BlockSize       = BlockHeaderSize + BlockDataSize // 65552

	ScryptN      = 16384
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 80
)

var DefaultSalt = [16]byte{
	0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
	0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
}

var (
	ErrBadMagic          = errors.New("bad magic bytes")
	ErrEncryptedTooShort = errors.New("encrypted file too short")
	ErrDecryptBlock      = errors.New("failed to decrypt block: wrong password or corrupt data")
	ErrFileIsDirectory   = errors.New("path is a directory") // unused, reserved for future validation
)

type Key struct {
	DataKey    [32]byte
	NameKey    [32]byte
	NameTweak  [16]byte
}

func DeriveKey(password string, salt []byte) (*Key, error) {
	if len(salt) == 0 {
		s := DefaultSalt
		salt = s[:]
	}
	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	k := &Key{}
	copy(k.DataKey[:], key[0:32])
	copy(k.NameKey[:], key[32:64])
	copy(k.NameTweak[:], key[64:80])
	return k, nil
}

func newNonce() *[FileNonceSize]byte {
	n := &[FileNonceSize]byte{}
	rand.Read(n[:])
	return n
}

func incrementNonce(n *[FileNonceSize]byte) {
	for i := 0; i < len(n); i++ {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

func EncryptedSize(plaintextSize int64) int64 {
	blocks := plaintextSize / BlockDataSize
	residue := plaintextSize % BlockDataSize
	es := int64(FileHeaderSize) + blocks*int64(BlockSize)
	if residue != 0 {
		es += int64(BlockHeaderSize) + residue
	}
	return es
}

func DecryptedSize(encryptedSize int64) (int64, error) {
	size := encryptedSize - int64(FileHeaderSize)
	if size < 0 {
		return 0, ErrEncryptedTooShort
	}
	blocks := size / int64(BlockSize)
	residue := size % int64(BlockSize)
	ds := blocks * int64(BlockDataSize)
	if residue != 0 {
		residue -= int64(BlockHeaderSize)
		if residue <= 0 {
			return 0, ErrEncryptedTooShort
		}
		ds += residue
	}
	return ds, nil
}

func Encrypt(w io.Writer, r io.Reader, password string, salt []byte) (int64, error) {
	key, err := DeriveKey(password, salt)
	if err != nil {
		return 0, err
	}

	n := newNonce()

	header := make([]byte, FileHeaderSize)
	copy(header[0:8], FileMagic)
	copy(header[8:32], n[:])
	if _, err := w.Write(header); err != nil {
		return 0, fmt.Errorf("write header: %w", err)
	}

	totalWritten := int64(FileHeaderSize)
	buf := make([]byte, BlockDataSize)

	for {
		bytesRead := 0
		for bytesRead < BlockDataSize {
			nn, err := r.Read(buf[bytesRead:])
			bytesRead += nn
			if err == io.EOF {
				if bytesRead > 0 {
					out := secretbox.Seal(nil, buf[:bytesRead], n, &key.DataKey)
					if _, err := w.Write(out); err != nil {
						return totalWritten, fmt.Errorf("write block: %w", err)
					}
					totalWritten += int64(len(out))
				}
				return totalWritten, nil
			}
			if err != nil {
				return totalWritten, fmt.Errorf("read: %w", err)
			}
			if bytesRead == BlockDataSize {
				break
			}
		}

		out := secretbox.Seal(nil, buf[:BlockDataSize], n, &key.DataKey)
		if _, err := w.Write(out); err != nil {
			return totalWritten, fmt.Errorf("write block: %w", err)
		}
		totalWritten += int64(len(out))
		incrementNonce(n)
	}
}

func Decrypt(w io.Writer, r io.Reader, password string, salt []byte) (int64, error) {
	key, err := DeriveKey(password, salt)
	if err != nil {
		return 0, err
	}

	header := make([]byte, FileHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, fmt.Errorf("read header: %w", err)
	}

	if string(header[0:8]) != FileMagic {
		return 0, ErrBadMagic
	}

	var n [FileNonceSize]byte
	copy(n[:], header[8:32])

	totalWritten := int64(0)
	buf := make([]byte, BlockSize)

	for {
		if _, err := io.ReadFull(r, buf[:BlockHeaderSize]); err != nil {
			if err == io.EOF {
				break
			}
			return totalWritten, fmt.Errorf("read auth tag: %w", err)
		}

		dataLen := 0
		for dataLen < BlockDataSize {
			nn, err := r.Read(buf[BlockHeaderSize+dataLen:])
			dataLen += nn
			if err != nil {
				if err == io.EOF {
					break
				}
				return totalWritten, fmt.Errorf("read data: %w", err)
			}
		}

		blockLen := BlockHeaderSize + dataLen

		plaintext, ok := secretbox.Open(nil, buf[:blockLen], &n, &key.DataKey)
		if !ok {
			return totalWritten, ErrDecryptBlock
		}

		if _, err := w.Write(plaintext); err != nil {
			return totalWritten, fmt.Errorf("write plaintext: %w", err)
		}
		totalWritten += int64(len(plaintext))
		incrementNonce(&n)

		if dataLen < BlockDataSize {
			break
		}
	}

	return totalWritten, nil
}

func EncryptFile(inputPath, outputPath, password string, salt []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	_, err = Encrypt(outFile, inFile, password, salt)
	return err
}

func DecryptFile(inputPath, outputPath, password string, salt []byte) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	_, err = Decrypt(outFile, inFile, password, salt)
	return err
}
