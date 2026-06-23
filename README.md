# rclone-encrypt

A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- [rclone](https://github.com/rclone/rclone)
- [rclonedecrypt](https://github.com/mcolatosti/rclonedecrypt)
- [rclone-rcc](https://github.com/br0kenpixel/rclone-rcc)
- [@fyears/rclone-crypt](https://github.com/fyears/rclone-crypt)

## Installation

**Homebrew (macOS/Linux)**
```bash
brew tap yetanotherchris/rclone-encrypt https://github.com/yetanotherchris/rclone-encrypt
brew install rclone-encrypt
```

**Scoop (Windows)**
```powershell
scoop bucket add rclone-encrypt https://github.com/yetanotherchris/rclone-encrypt
scoop install rclone-encrypt
```

## Examples usage

### Basic encrypt/decrypt

```bash
# Encrypt a file (you will be prompted for a password)
rclone-encrypt encrypt document.txt document.txt.encrypted

# Decrypt a file
rclone-encrypt decrypt document.txt.encrypted document.txt
```

### With a custom salt

```bash
# Generate a salt (keep this if you want to decrypt later)
rclone-encrypt generate-salt

# Encrypt with a custom salt
rclone-encrypt encrypt --salt a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 input.txt output.bin

# Decrypt with the same salt
rclone-encrypt decrypt --salt a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 output.bin input.txt
```

### Supply password via environment variable (recommended)

```bash
export RCLONE_ENCRYPT_PASSWORD=mysecret
rclone-encrypt encrypt input.txt output.bin
```

### Supply salt via environment variable

```bash
export RCLONE_ENCRYPT_SALT=deadbeefdeadbeefdeadbeefdeadbeef
rclone-encrypt encrypt input.txt output.bin
rclone-encrypt decrypt output.bin input.txt
```

### Automatic filename encryption (output optional)

When `--output` is omitted, the filenames are automatically encrypted/decrypted using AES-EME (matching rclone):

```bash
# Encrypt: output filename is derived from the input filename
# (only the content is encrypted—the derived name is rclone-compatible)
rclone-encrypt encrypt document.txt

# Decrypt: original filename is recovered from the encrypted filename
rclone-encrypt decrypt <encrypted-filename>

# --output still works to override the derived name
rclone-encrypt encrypt input.txt output.bin
```

### Supply password on command line (insecure)

**WARNING:** Using `--password` exposes the password in process listings and shell history. Consider using the `RCLONE_ENCRYPT_PASSWORD` environment variable or omitting the flag to be prompted securely.

```bash
rclone-encrypt encrypt --password "mysecret" input.txt output.bin
```

## Details

Rclone encryption uses:

- **NaCl SecretBox (XSalsa20 + Poly1305)** for file contents.
- **scrypt** (N=16384, r=8, p=1) for key derivation.
- **AES-EME** for filename encryption (32-byte key, 16-byte tweak).
- **Base32** encoding for encrypted filenames (lowercase, no padding) for case-insensitive FS compatibility.
- A **default salt** if none is provided (rclone-compatible).

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--password` | *(prompted)* | Encryption password (use env var `RCLONE_ENCRYPT_PASSWORD` instead when possible) |
| `--salt` | *(default rclone salt)* | Hex-encoded salt (omit to use rclone's default salt; also via `RCLONE_ENCRYPT_SALT` env var) |
| `-i`, `--input` | *(positional)* | Input file path |
| `-o`, `--output` | *(auto-derived)* | Output file path (omit to use AES-EME encrypted/decrypted filename) |

## Building from Source

Requires Go 1.25+.

```bash
git clone https://github.com/yetanotherchris/rclone-encrypt
cd rclone-encrypt
go build -o rclone-encrypt .
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest (`rclone-encrypt.json`) and Homebrew formula (`Formula/rclone-encrypt.rb`) in this repo.
