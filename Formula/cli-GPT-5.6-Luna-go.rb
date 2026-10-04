class CliGpt56LunaGo < Formula
  desc "Encrypt and decrypt files using rclone crypt defaults"
  homepage "https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases/download/v#{version}/cli-GPT-5.6-Luna-go_#{version}_darwin_arm64.tar.gz"
    else
      url "https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases/download/v#{version}/cli-GPT-5.6-Luna-go_#{version}_darwin_amd64.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases/download/v#{version}/cli-GPT-5.6-Luna-go_#{version}_linux_arm64.tar.gz"
    else
      url "https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases/download/v#{version}/cli-GPT-5.6-Luna-go_#{version}_linux_amd64.tar.gz"
    end
  end

  def install
    bin.install "cli-GPT-5.6-Luna-go"
  end
end
