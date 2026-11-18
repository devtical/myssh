#!/usr/bin/env bash
set -euo pipefail

VERSION="$1"
SHA256_INTEL="$2"
SHA256_ARM="$3"
SHA256_SOURCE="$4"
OUTPUT="${5:-Formula/myssh.rb}"

mkdir -p "$(dirname "$OUTPUT")"

cat > "$OUTPUT" <<RUBY
class Myssh < Formula
  desc "Inspect and manage SSH keys in your .ssh directory"
  homepage "https://github.com/devtical/myssh"
  license "Apache-2.0"

  on_macos do
    on_intel do
      url "https://github.com/devtical/myssh/releases/download/v${VERSION}/myssh-x86_64-apple-darwin.tar.gz"
      sha256 "${SHA256_INTEL}"
    end
    on_arm do
      url "https://github.com/devtical/myssh/releases/download/v${VERSION}/myssh-aarch64-apple-darwin.tar.gz"
      sha256 "${SHA256_ARM}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/devtical/myssh/archive/refs/tags/v${VERSION}.tar.gz"
      sha256 "${SHA256_SOURCE}"
    end
    on_arm do
      url "https://github.com/devtical/myssh/archive/refs/tags/v${VERSION}.tar.gz"
      sha256 "${SHA256_SOURCE}"
    end

    depends_on "rust" => :build
  end

  def install
    if OS.mac?
      bin.install "myssh"
    else
      system "cargo", "install", *std_cargo_args
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/myssh --version")
  end
end
RUBY
