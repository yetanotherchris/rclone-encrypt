class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.2/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "d4795d2a621032dc9f1a4b1e7eb75fe753ee202477f136a7f6f26d8f2c93386d"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.2/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "153ca4dda6803e48f7269fcb2fd6bc9ca2eb8c62c87aae599ce09d545ecbd8b3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.2/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "44d6fcf1961a8715f5f3d4bf84f701aeffe3c981780f0ff88091e34a6b4d2d89"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.2/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "83bd8e018579126bf660adf19bf9d96437bb39e010ca6d34d87a8fad17f2a682"
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