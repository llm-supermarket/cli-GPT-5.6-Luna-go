package crypt

import "testing"

func TestDataAndFilenameRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		salt     string
		encoding FilenameEncoding
	}{{"", Base32}, {"pepper", Base64}} {
		c, err := New("Testpassword1", tc.salt, tc.encoding)
		if err != nil {
			t.Fatal(err)
		}
		name := "report with spaces.txt"
		encoded := c.EncryptFilename(name)
		decoded, err := c.DecryptFilename(encoded)
		if err != nil || decoded != name {
			t.Fatalf("filename round trip: %q, %v", decoded, err)
		}
		data := []byte("authenticated content")
		ciphertext, err := c.EncryptData(data)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := c.DecryptData(ciphertext)
		if err != nil || string(plaintext) != string(data) {
			t.Fatalf("data round trip: %q, %v", plaintext, err)
		}
	}
}
