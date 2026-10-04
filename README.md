# cli-GPT-5.6-Luna-go

`cli-GPT-5.6-Luna-go` encrypts and decrypts individual files using the rclone
crypt data and filename defaults. It is a self-contained Go binary, so users do
not need to install Go, Python, Java, or another runtime.

## Installation

### GitHub releases

Download the archive for your operating system and architecture from the
[Releases](https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases)
page, then put the `cli-GPT-5.6-Luna-go` binary on your `PATH`.

### Scoop

After a release is published, install the manifest from this repository (or a
Scoop bucket containing it):

```powershell
scoop install https://github.com/llm-supermarket/cli-GPT-5.6-Luna-go/releases/latest/download/cli-GPT-5.6-Luna-go.json
```

### Homebrew

```bash
brew install llm-supermarket/tap/cli-GPT-5.6-Luna-go
```

The formula is intended for the `llm-supermarket/homebrew-tap` repository.

## Usage

The input file is always required with `-i` or `--input-file`. If `-o` or
`--output-file` is omitted, encryption writes next to the input using the
encrypted filename, and decryption writes next to the input using the restored
filename. The default filename encoding is rclone's lowercase, unpadded
base32. `base64` is also supported.

The command prompts for a password and an optional salt:

```bash
cli-GPT-5.6-Luna-go encrypt --input-file report.txt
cli-GPT-5.6-Luna-go decrypt --input-file kr9tu4e1da4u3nifdd99g9tf5o
```

For automation, pass the password explicitly. This can expose it through shell
history and process listings. Prefer an environment variable, and remove the
command from your shell history afterwards:

```bash
export FILE_PASSWORD='Testpassword1'
cli-GPT-5.6-Luna-go encrypt -i report.txt -o encrypted.bin \
  --password-env FILE_PASSWORD --salt 'optional salt' --filename-encoding base64
cli-GPT-5.6-Luna-go decrypt -i encrypted.bin -o report.txt \
  --password-env FILE_PASSWORD --salt 'optional salt' --filename-encoding base64
```

`--password` prints a warning every time it is used. The salt is optional; when
omitted, the fixed rclone-compatible default salt is used. A custom salt must
be supplied for both encryption and decryption.

## Development

```bash
go test ./...
go build ./cmd/cli-GPT-5.6-Luna-go
```

The implementation uses rclone-compatible scrypt key derivation, EME/AES
filename encryption, and authenticated secretbox data blocks.
