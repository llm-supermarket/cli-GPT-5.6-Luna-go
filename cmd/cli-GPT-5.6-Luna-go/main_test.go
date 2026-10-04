package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEncryptDecryptWithPasswordAndBase64(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(input, []byte("secret contents"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"encrypt", "-i", input, "--password", "Testpassword1", "--salt", "pepper", "--filename-encoding", "base64"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	encrypted := strings.TrimSpace(stdout.String())
	if filepath.Base(encrypted) == "hello.txt" || !strings.Contains(stderr.String(), "--password") {
		t.Fatalf("unexpected encryption output: %q %q", encrypted, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"decrypt", "-i", encrypted, "--password", "Testpassword1", "--salt", "pepper", "--filename-encoding", "base64"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	decrypted := strings.TrimSpace(stdout.String())
	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret contents" {
		t.Fatalf("decrypted content = %q", got)
	}
}

func TestCLIPromptsForPasswordAndSalt(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "prompt.txt")
	if err := os.WriteFile(input, []byte("prompted"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"encrypt", "-i", input}, strings.NewReader("Testpassword1\npepper\n"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Password:") || !strings.Contains(stdout.String(), "Salt (optional):") {
		t.Fatalf("prompts missing: %q", stdout.String())
	}
}

func TestCLIEncryptDecryptWithoutSalt(t *testing.T) {
	t.Setenv("CLI_TEST_PASSWORD", "Testpassword1")
	dir := t.TempDir()
	input := filepath.Join(dir, "no-salt.txt")
	if err := os.WriteFile(input, []byte("default salt"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"encrypt", "-i", input, "--password-env", "CLI_TEST_PASSWORD"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	encrypted := strings.TrimSpace(stdout.String())
	stdout.Reset()
	if err := run([]string{"decrypt", "-i", encrypted, "--password-env", "CLI_TEST_PASSWORD"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	decrypted := strings.TrimSpace(stdout.String())
	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "default salt" {
		t.Fatalf("decrypted content = %q", got)
	}
}
