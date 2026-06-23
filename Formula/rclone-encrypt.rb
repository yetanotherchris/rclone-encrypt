class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/yetanotherchris/rclone-encrypt"
  version "1.0.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.1/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "315ef7bb1cd48af23ab1b3ab6c1654cf5311aa1501e448de10dc47b4fe6284b5"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.1/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "c3ef8dc2f41dbd04116396bb09052794fd9ef1371cf01fc07ddc685e528a97d2"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.1/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "ed725ccdd62a1e1a84e64fcd66079cf0c0dc17d76538d4acbbc2435fa643f153"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt/releases/download/v1.0.1/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "02349256440f645aef47352e7699db98fbff1508a0c880919412ed0a267aa5c4"
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