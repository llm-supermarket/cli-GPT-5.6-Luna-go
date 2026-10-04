package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/llm-supermarket/cli-GPT-5.6-Luna-go/internal/crypt"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("operation required: use encrypt or decrypt")
	}
	operation := strings.ToLower(args[0])
	if operation != "encrypt" && operation != "decrypt" {
		return fmt.Errorf("unknown operation %q: use encrypt or decrypt", args[0])
	}
	fs := flag.NewFlagSet(operation, flag.ContinueOnError)
	fs.SetOutput(errOut)
	input := fs.String("input-file", "", "input file (required)")
	fs.StringVar(input, "i", "", "input file (required)")
	output := fs.String("output-file", "", "output file (optional)")
	fs.StringVar(output, "o", "", "output file (optional)")
	password := fs.String("password", "", "password (warning: visible in process listings and shell history)")
	passwordEnv := fs.String("password-env", "", "read the password from this environment variable")
	salt := fs.String("salt", "", "optional salt")
	encoding := fs.String("filename-encoding", "base32", "encrypted filename encoding: base32 or base64")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *input == "" {
		return errors.New("-i/--input-file is required")
	}
	if *password != "" && *passwordEnv != "" {
		return errors.New("use only one of --password and --password-env")
	}
	if fs.Lookup("password").Value.String() != "" {
		fmt.Fprintln(errOut, "warning: --password can be exposed in process listings and shell history; prefer an environment variable and wipe this history entry")
	}
	pass := *password
	if *passwordEnv != "" {
		var ok bool
		pass, ok = os.LookupEnv(*passwordEnv)
		if !ok {
			return fmt.Errorf("password environment variable %q is not set", *passwordEnv)
		}
	}
	passwordPrompted := false
	if pass == "" {
		passwordPrompted = true
		var err error
		pass, err = promptSecret(in, out, "Password: ")
		if err != nil {
			return err
		}
	}
	if *salt == "" {
		interactive := false
		if f, ok := in.(*os.File); ok {
			interactive = term.IsTerminal(int(f.Fd()))
		}
		if passwordPrompted || interactive {
			var err error
			*salt, err = promptOptional(in, out, "Salt (optional): ")
			if err != nil {
				return err
			}
		}
	}
	cipher, err := crypt.New(pass, *salt, crypt.FilenameEncoding(strings.ToLower(*encoding)))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var result []byte
	var name string
	if operation == "encrypt" {
		result, err = cipher.EncryptData(data)
		name = cipher.EncryptFilename(filepath.Base(*input))
	} else {
		result, err = cipher.DecryptData(data)
		name, err = cipher.DecryptFilename(filepath.Base(*input))
	}
	if err != nil {
		return err
	}
	destination := *output
	if destination == "" {
		destination = filepath.Join(filepath.Dir(*input), name)
	}
	if err := os.WriteFile(destination, result, 0600); err != nil {
		return err
	}
	fmt.Fprintln(out, destination)
	return nil
}

func promptSecret(in io.Reader, out io.Writer, prompt string) (string, error) {
	f, ok := in.(*os.File)
	if ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(out, prompt)
		value, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(out)
		return string(value), err
	}
	return promptLine(in, out, prompt, false)
}

func promptOptional(in io.Reader, out io.Writer, prompt string) (string, error) {
	return promptLine(in, out, prompt, true)
}
func promptLine(in io.Reader, out io.Writer, prompt string, optional bool) (string, error) {
	fmt.Fprint(out, prompt)
	var value string
	_, err := fmt.Fscanln(in, &value)
	if err == io.EOF && optional {
		return "", nil
	}
	return value, err
}
