#!/usr/bin/env bash
set -euo pipefail

VERSION="$1"
SHA256_INTEL="$2"
SHA256_ARM="$3"
OUTPUT="${4:-Formula/myssh.rb}"

mkdir -p "$(dirname "$OUTPUT")"

cat > "$OUTPUT" <<RUBY
class Myssh < Formula
  desc "Inspect and manage SSH keys in your .ssh directory"
  homepage "https://github.com/devtical/myssh"
  version "${VERSION}"
  license "Apache-2.0"

  depends_on macos: :monterey

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

  def install
    bin.install "myssh"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/myssh --version")
  end
end
RUBY
