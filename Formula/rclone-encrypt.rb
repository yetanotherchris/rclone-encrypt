class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "44173d750f137f4d0ae93d2add320d7745c7cd96e22b5c50ca545ca37c47496b"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "71eae70b5c1c837acb63d3d320478321581de90424a5a0149f919160214b0f08"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "227f9d3c79ba0a05fff21d407686fc27058e19b770c7746cd00f6dbbf122eb10"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "138313bcab0517d2d2d02907600456f8e0054557de1e819a20197b9bc92c931e"
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