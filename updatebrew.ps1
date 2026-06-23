param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "yetanotherchris/rclone-encrypt"
$platforms = @("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64")
$formulaPath = "$PSScriptRoot/Formula/rclone-encrypt.rb"
$base = "https://github.com/$repo/releases/download/v$Version"

$hash = @{}
foreach ($platform in $platforms) {
    $url = "$base/rclone-encrypt-$platform.tar.gz"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "rclone-encrypt-$platform.tar.gz"

    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile

    $hash[$platform] = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"

    Remove-Item $tempFile
}

$formula = @"
class RcloneEncrypt < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-darwin-arm64.tar.gz"
      sha256 "$($hash['darwin-arm64'])"
    else
      url "$base/rclone-encrypt-darwin-amd64.tar.gz"
      sha256 "$($hash['darwin-amd64'])"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-linux-arm64.tar.gz"
      sha256 "$($hash['linux-arm64'])"
    else
      url "$base/rclone-encrypt-linux-amd64.tar.gz"
      sha256 "$($hash['linux-amd64'])"
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
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"
