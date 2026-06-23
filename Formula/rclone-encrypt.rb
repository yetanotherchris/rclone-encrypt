class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.4/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "4b177ac5235f7e0e46ea49715378efbd328415fe758193f2db484c17b087dff1"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.4/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "73871018b093e39da31b0b9deff4378e93121543392df1c79b68d025afe39f87"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.4/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "4612bf0d566fec78a34eab3c814a81f75ab0b8721d2438c2b473abea12a6a507"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.4/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "530359212f69a170c0dbc01c3d0a8820aaf85e4555489f93abc53bd2ac7d79d5"
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