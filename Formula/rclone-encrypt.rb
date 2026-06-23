class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v0.1.0/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v0.1.0/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v0.1.0/rclone-encrypt-linux-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v0.1.0/rclone-encrypt-linux-amd64.tar.gz"
      sha256 ""
    end
  end

  def install
    bin.install "rclone-encrypt-darwin-arm64" => "rclone-encrypt" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-darwin-amd64" => "rclone-encrypt" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-linux-arm64" => "rclone-encrypt" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-linux-amd64" => "rclone-encrypt" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt #{version}", shell_output("#{bin}/rclone-encrypt version")
  end
end
