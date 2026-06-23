class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.3/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "24e284301903e1f00698ddf8406f33f8e1e8087cfc51ed956689dea29e0f28a9"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.3/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "d2996607f5f5c2bd2c44c2d93fb6c785cfd3b9ec292f55bce0b26b683ec8a2dc"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.3/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "01134ff6ef9d8be6593d3047affcd313eb39030d78d5c7bb3aea50d99e840616"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.3/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "8e5b29393fa3a3e89a4e4576dc0d72e462cc9cb852de48eec03415f4e9e5a9e6"
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