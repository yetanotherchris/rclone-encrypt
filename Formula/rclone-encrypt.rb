class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.5"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.5/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "e8970b61ff06e07409a2305214c3fbe0835480552b93d610278ec4df23223c72"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.5/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "5cad1b8b02ded0c2da43ace36c5e7fdf27e019cbd69e0c7134ae01a217b1f31c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.5/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "62fe34d4f2852008bcee013e53aa3a0935de5d2cf7355d07a8193e211c0870c4"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.5/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "982c00068b9fccf55904328afad7e1cd3f2404c746daa008ca8bda021909da4f"
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