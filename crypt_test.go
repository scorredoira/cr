package main

import "testing"

func TestMustFail(t *testing.T) {
	e, err := Encrypts("The world wonders", "Nimitz")
	if err != nil {
		t.Fatal(err)
	}

	// try to decrypt with the wrong password.
	_, err = Decrypts(e, "Halsey")
	if err == nil {
		t.Fatal("Should have returned an error.")
	}
}

func TestEncrypt(t *testing.T) {
	e, err := Encrypts("The world wonders", "Nimitz")
	if err != nil {
		t.Fatal(err)
	}

	d, err := Decrypts(e, "Nimitz")
	if err != nil {
		t.Fatal(err)
	}

	if d != "The world wonders" {
		t.Fatal("Error decrypting")
	}
}

func TestUnique(t *testing.T) {
	a, err := Encrypts("The world wonders", "Nimitz")
	if err != nil {
		t.Fatal(err)
	}

	b, err := Encrypts("The world wonders", "Nimitz")
	if err != nil {
		t.Fatal(err)
	}

	if a == b {
		t.Fatal("Should be different", a, b)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Encrypts("The world wonders", "Nimitz")
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkDecrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := Decrypts("BX6Kj4ZRSo8M+gEGvBmYs/D5kD/N23WXtmfQJhbNl0ma/ZpGSfXp5TU78niN6OY+", "Nimitz")
		if err != nil {
			b.Fatal(err)
		}
	}
}
