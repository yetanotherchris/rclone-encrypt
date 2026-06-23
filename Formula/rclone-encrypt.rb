class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "9e38f7c109d9208ac3c1a7d08bbf37631f6b45eefc9bfb37698bbdf4e5ac0030"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "b02b22e2f3d3e24c61c9f4c044ce3cc61c29100dee4903f8cf2edcc12aa0eae5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "7d3e1dc0d73518d6f6daeb79fbbaf16e7fb7dcb425a121662a0ba4940bf88f74"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.0/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "4f18a0f35344c9471bfa11aea42f7b092f0926f1f9de958dc186d5159df16531"
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