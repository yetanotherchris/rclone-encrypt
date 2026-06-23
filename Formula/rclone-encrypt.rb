class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "d9e48fce9bf0f1f453d5e650b90e281a3d53b9665687ff4af812c5f6c5a9516f"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "689794ef63806b9fb4658bc971c87a54bd04ab3acc3bf3ba9e0452e418a8b491"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "fcb7cf1bcbf464d60a2b380bd553776974a2628dc1c5e0e34ef063c353f50e28"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "76470b3232a9c852ff8d8ea88fe522932fd8260228c7f555ab15623fa4ee6da6"
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