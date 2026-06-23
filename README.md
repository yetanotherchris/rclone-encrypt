# rclone-encrypt

A small CLI tool that encrypts and decrypts files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt).

## Installation

**Homebrew (macOS/Linux)**

brew tap yetanotherchris/rclone-encrypt https://github.com/yetanotherchris/rclone-encrypt
brew install rclone-encrypt

**Scoop (Windows)**

scoop bucket add rclone-encrypt https://github.com/yetanotherchris/rclone-encrypt
scoop install rclone-encrypt

## Usage

### Encrypt a file

rclone-encrypt encrypt input.txt output.bin
rclone-encrypt encrypt --salt deadbeefdeadbeefdeadbeefdeadbeef input.txt output.bin

### Decrypt a file

rclone-encrypt decrypt output.bin decrypted.txt

### Supply password via environment variable (recommended)

export RCLONE_ENCRYPT_PASSWORD=mysecret
rclone-encrypt encrypt input.txt output.bin

### Supply password on command line (insecure)

**WARNING:** Using `--password` exposes the password in process listings and shell history. Consider using the `RCLONE_ENCRYPT_PASSWORD` environment variable or omitting the flag to be prompted securely.

rclone-encrypt encrypt --password "mysecret" input.txt output.bin

### Generate a salt

rclone-encrypt generate-salt

Supply the salt to encrypt/decrypt:

rclone-encrypt encrypt --salt "$(rclone-encrypt generate-salt)" input.txt output.bin

## Details

Rclone encryption uses:

- **NaCl SecretBox (XSalsa20 + Poly1305)** for file contents (defaults in rclone).
- **scrypt** (N=16384, r=8, p=1) for key derivation.
- A **default salt** if none is provided (rclone-compatible).

## Building from Source

Requires Go 1.25+.

git clone https://github.com/yetanotherchris/rclone-encrypt
cd rclone-encrypt
go build -o rclone-encrypt .

## Similar tools

- [rclone](https://rclone.org/) - the full rclone tool with encryption support
- [rclonedecrypt](https://github.com/mcolatosti/rclonedecrypt)
- [rclone-rcc](https://github.com/br0kenpixel/rclone-rcc)
- [rclone-crypt](https://github.com/fyears/rclone-crypt)
